use super::response::{error_stream_end, error_synapse_response, rejected_handshake_preauth};
use super::{handshake, ServerContext};
use crate::types::{
    read_frame, write_frame, write_frame_and_finish, HandshakeRequest, MessageType, StreamChunk,
    StreamEnd, SynapsePacket, SynapseResponse,
};
use crate::util::unix_timestamp_secs;
use quinn::{Connection, RecvStream, SendStream};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

pub(super) async fn handle_connection(connection: Connection, ctx: ServerContext) {
    let connection = Arc::new(connection);
    let stable_id = connection.stable_id();
    let remote = connection.remote_address();
    debug!(stable_id, %remote, "handle_connection: entering accept_bi loop");

    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                debug!(stable_id, "handle_connection: accepted bi stream");
                let conn = connection.clone();
                let ctx = ctx.clone();

                tokio::spawn(async move {
                    handle_stream(send, recv, conn, ctx).await;
                });
            }
            Err(e) => {
                let close_reason = connection.close_reason();
                info!(
                    remote = %connection.remote_address(),
                    error = %e,
                    close_reason = ?close_reason,
                    "QUIC connection stream loop ended"
                );
                break;
            }
        }
    }

    let remote_addr = connection.remote_address();
    let mut connections = ctx.connections.write().await;
    let mut addr_index = ctx.addr_to_hotkey.write().await;
    let mut cleaned = false;
    if let Some(hotkey) = addr_index.get(&remote_addr).cloned() {
        if let Some(existing) = connections.get(&hotkey) {
            if Arc::ptr_eq(&existing.connection, &connection) {
                super::remove_hotkey_from_maps(&mut connections, &mut addr_index, &hotkey);
                cleaned = true;
            }
        }
    }
    if !cleaned {
        let stale_hotkey = connections
            .iter()
            .find(|(_, v)| Arc::ptr_eq(&v.connection, &connection))
            .map(|(k, _)| k.clone());
        if let Some(hotkey) = stale_hotkey {
            warn!(
                "Stale connection cleanup via fallback scan for validator: {}",
                hotkey
            );
            super::remove_hotkey_from_maps(&mut connections, &mut addr_index, &hotkey);
        }
    }
    drop(addr_index);
    drop(connections);
    connection.close(0u32.into(), b"done");
}

async fn handle_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    connection: Arc<quinn::Connection>,
    ctx: ServerContext,
) {
    let frame = match read_frame(&mut recv, ctx.config.max_frame_payload_bytes).await {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to read frame: {}", e);
            return;
        }
    };

    debug!(msg_type = ?frame.0, payload_len = frame.1.len(), "handle_stream: frame received");
    match frame {
        (MessageType::SynapsePacket, payload) => {
            let packet: SynapsePacket = match rmp_serde::from_slice(&payload) {
                Ok(p) => p,
                Err(e) => {
                    warn!("Failed to parse synapse packet: {}", e);
                    let err_response = error_synapse_response("invalid request format");
                    if let Ok(bytes) = rmp_serde::to_vec(&err_response) {
                        let _ =
                            write_frame_and_finish(&mut send, MessageType::SynapseResponse, &bytes)
                                .await;
                    }
                    return;
                }
            };

            let is_streaming = {
                let handlers = ctx.streaming_handlers.read().await;
                handlers.contains_key(&packet.synapse_type)
            };

            let handler_timeout = Duration::from_secs(ctx.config.handler_timeout_secs);

            if is_streaming {
                handle_streaming_synapse_with_timeout(
                    send,
                    packet,
                    connection,
                    &ctx,
                    handler_timeout,
                )
                .await;
            } else {
                let response = match tokio::time::timeout(
                    handler_timeout,
                    process_synapse_packet(packet, connection.clone(), &ctx),
                )
                .await
                {
                    Ok(resp) => resp,
                    Err(_) => {
                        warn!(
                            "Handler timed out after {}s",
                            ctx.config.handler_timeout_secs
                        );
                        error_synapse_response("handler timed out")
                    }
                };
                match rmp_serde::to_vec(&response) {
                    Ok(bytes) => {
                        let _ =
                            write_frame_and_finish(&mut send, MessageType::SynapseResponse, &bytes)
                                .await;
                    }
                    Err(e) => {
                        error!("Failed to serialize SynapseResponse: {}", e);
                        let fallback = error_synapse_response("internal serialization error");
                        if let Ok(bytes) = rmp_serde::to_vec(&fallback) {
                            let _ = write_frame_and_finish(
                                &mut send,
                                MessageType::SynapseResponse,
                                &bytes,
                            )
                            .await;
                        }
                    }
                }
            }
        }
        (MessageType::HandshakeRequest, payload) => {
            let remote_ip = connection.remote_address().ip();
            if !handshake::check_handshake_rate(&ctx, remote_ip).await {
                warn!("Handshake rate limit exceeded for {}", remote_ip);
                let reject = rejected_handshake_preauth();
                if let Ok(bytes) = rmp_serde::to_vec(&reject) {
                    let _ =
                        write_frame_and_finish(&mut send, MessageType::HandshakeResponse, &bytes)
                            .await;
                }
                return;
            }

            let request: HandshakeRequest = match rmp_serde::from_slice(&payload) {
                Ok(r) => r,
                Err(e) => {
                    warn!("Failed to parse handshake request: {}", e);
                    let err_response = rejected_handshake_preauth();
                    if let Ok(bytes) = rmp_serde::to_vec(&err_response) {
                        let _ = write_frame_and_finish(
                            &mut send,
                            MessageType::HandshakeResponse,
                            &bytes,
                        )
                        .await;
                    }
                    return;
                }
            };

            let timeout_duration = Duration::from_secs(ctx.config.handshake_timeout_secs);
            let response = match tokio::time::timeout(
                timeout_duration,
                handshake::process_handshake(request, connection.clone(), &ctx),
            )
            .await
            {
                Ok(resp) => resp,
                Err(_) => {
                    warn!("Handshake processing timed out for {}", remote_ip);
                    super::response::rejected_handshake(&ctx.miner_hotkey, unix_timestamp_secs())
                }
            };
            match rmp_serde::to_vec(&response) {
                Ok(bytes) => {
                    let _ =
                        write_frame_and_finish(&mut send, MessageType::HandshakeResponse, &bytes)
                            .await;
                }
                Err(e) => {
                    error!("Failed to serialize HandshakeResponse: {}", e);
                    let fallback = super::response::rejected_handshake(
                        &ctx.miner_hotkey,
                        unix_timestamp_secs(),
                    );
                    if let Ok(bytes) = rmp_serde::to_vec(&fallback) {
                        let _ = write_frame_and_finish(
                            &mut send,
                            MessageType::HandshakeResponse,
                            &bytes,
                        )
                        .await;
                    }
                }
            }
        }
        (msg_type, _) => {
            warn!("Unexpected message type on server: {:?}", msg_type);
            let _ = send.finish();
        }
    }
}

pub(super) async fn verify_synapse_auth(
    connection: &Arc<quinn::Connection>,
    ctx: &ServerContext,
) -> std::result::Result<String, SynapseResponse> {
    let validator_hotkey = {
        let addr_index = ctx.addr_to_hotkey.read().await;
        match addr_index.get(&connection.remote_address()).cloned() {
            Some(hotkey) => hotkey,
            None => {
                error!(
                    "Unknown or unauthenticated connection from {}",
                    connection.remote_address()
                );
                return Err(error_synapse_response("authentication failed"));
            }
        }
    };

    {
        let connections_guard = ctx.connections.read().await;
        if let Some(conn) = connections_guard.get(&validator_hotkey) {
            if !conn.is_verified() {
                error!(
                    "Connection not verified for validator: {}",
                    validator_hotkey
                );
                return Err(error_synapse_response("authentication failed"));
            }
            conn.update_activity();
        } else {
            error!("No connection found for validator {}", validator_hotkey);
            return Err(error_synapse_response("authentication failed"));
        }
    }

    Ok(validator_hotkey)
}

async fn handle_streaming_synapse_with_timeout(
    mut send: SendStream,
    packet: SynapsePacket,
    connection: Arc<quinn::Connection>,
    ctx: &ServerContext,
    timeout: Duration,
) {
    if let Err(err_response) = verify_synapse_auth(&connection, ctx).await {
        let end = StreamEnd {
            success: false,
            error: err_response.error,
        };
        if let Ok(bytes) = rmp_serde::to_vec(&end) {
            let _ = write_frame_and_finish(&mut send, MessageType::StreamEnd, &bytes).await;
        }
        return;
    }

    let handler = {
        let handlers = ctx.streaming_handlers.read().await;
        match handlers.get(&packet.synapse_type) {
            Some(h) => h.clone(),
            None => {
                error!(
                    "No streaming handler registered for synapse type: {}",
                    packet.synapse_type
                );
                let end = error_stream_end("unrecognized synapse type");
                if let Ok(bytes) = rmp_serde::to_vec(&end) {
                    let _ = write_frame_and_finish(&mut send, MessageType::StreamEnd, &bytes).await;
                }
                return;
            }
        }
    };

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(ctx.config.streaming_channel_buffer);
    let synapse_type = packet.synapse_type.clone();

    let handle = tokio::spawn(async move { handler.handle(&synapse_type, packet.data, tx).await });

    let stream_result = tokio::time::timeout(timeout, async {
        while let Some(chunk_data) = rx.recv().await {
            let chunk = StreamChunk { data: chunk_data };
            match rmp_serde::to_vec(&chunk) {
                Ok(bytes) => {
                    if let Err(e) = write_frame(&mut send, MessageType::StreamChunk, &bytes).await {
                        error!("Failed to write stream chunk: {}", e);
                        return false;
                    }
                }
                Err(e) => {
                    error!("Failed to serialize stream chunk: {}", e);
                    return false;
                }
            }
        }
        true
    })
    .await;
    drop(rx);

    let end = match stream_result {
        Err(_) => {
            handle.abort();
            warn!("Streaming handler timed out after {}s", timeout.as_secs());
            error_stream_end("handler timed out")
        }
        Ok(false) => {
            handle.abort();
            error_stream_end("stream write failed")
        }
        Ok(true) => match handle.await {
            Ok(Ok(())) => StreamEnd {
                success: true,
                error: None,
            },
            Ok(Err(e)) => {
                error!("Streaming handler error: {}", e);
                error_stream_end("stream processing failed")
            }
            Err(e) if e.is_cancelled() => {
                warn!("Streaming handler task cancelled");
                error_stream_end("stream processing failed")
            }
            Err(e) => {
                error!("Streaming handler panicked: {}", e);
                error_stream_end("stream processing failed")
            }
        },
    };

    if let Ok(bytes) = rmp_serde::to_vec(&end) {
        let _ = write_frame_and_finish(&mut send, MessageType::StreamEnd, &bytes).await;
    }
}

async fn process_synapse_packet(
    packet: SynapsePacket,
    connection: Arc<quinn::Connection>,
    ctx: &ServerContext,
) -> SynapseResponse {
    let validator_hotkey = match verify_synapse_auth(&connection, ctx).await {
        Ok(hotkey) => hotkey,
        Err(err_response) => return err_response,
    };
    debug!(
        "Processing {} synapse from {}",
        packet.synapse_type, validator_hotkey
    );

    let async_handlers = ctx.async_handlers.read().await;
    if let Some(handler) = async_handlers.get(&packet.synapse_type) {
        let handler = Arc::clone(handler);
        drop(async_handlers);
        match handler.handle(&packet.synapse_type, packet.data).await {
            Ok(response_data) => SynapseResponse {
                success: true,
                data: response_data,
                timestamp: unix_timestamp_secs(),
                error: None,
            },
            Err(e) => {
                error!("Handler error for {}: {}", packet.synapse_type, e);
                error_synapse_response("request processing failed")
            }
        }
    } else {
        drop(async_handlers);
        let handlers = ctx.synapse_handlers.read().await;
        if let Some(handler) = handlers.get(&packet.synapse_type).cloned() {
            drop(handlers);
            let synapse_type = packet.synapse_type;
            let synapse_type_log = synapse_type.clone();
            // SynapseHandler::handle runs on Tokio's blocking thread pool.
            // tokio::time::timeout causes the waiting future to return Elapsed
            // and drops the JoinHandle, but does NOT cancel or interrupt the
            // underlying spawn_blocking task — it will run to completion and
            // occupy a blocking thread for its full duration. Keep sync
            // handlers fast or use AsyncSynapseHandler for long-running work.
            match tokio::task::spawn_blocking(move || handler.handle(&synapse_type, packet.data))
                .await
            {
                Ok(Ok(response_data)) => SynapseResponse {
                    success: true,
                    data: response_data,
                    timestamp: unix_timestamp_secs(),
                    error: None,
                },
                Ok(Err(e)) => {
                    error!("Handler error for {}: {}", synapse_type_log, e);
                    error_synapse_response("request processing failed")
                }
                Err(e) => {
                    error!("Handler task panicked for {}: {}", synapse_type_log, e);
                    error_synapse_response("request processing failed")
                }
            }
        } else {
            error!(
                "No handler registered for synapse type: {}",
                packet.synapse_type
            );
            error_synapse_response("unrecognized synapse type")
        }
    }
}
