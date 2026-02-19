use crate::connection_pool::ConnectionPool;
use crate::error::{LightningError, Result};
use crate::signing::Signer;
use crate::types::{
    read_frame, write_frame_and_finish, HandshakeRequest, HandshakeResponse, MessageType,
    QuicAxonInfo, QuicRequest, QuicResponse, StreamChunk, StreamEnd, SynapsePacket,
    SynapseResponse, MAX_RESPONSE_SIZE,
};
use crate::util::{unix_timestamp_millis, unix_timestamp_secs};
use base64::{prelude::BASE64_STANDARD, Engine};
use quinn::{ClientConfig, Connection, Endpoint, IdleTimeout, TransportConfig};
use rustls::ClientConfig as RustlsClientConfig;
use sp_core::{blake2_256, crypto::Ss58Codec, sr25519, Pair};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::Instant;
use tracing::{error, info, warn};

pub struct ClientConfig_ {
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub keep_alive_interval: Duration,
    pub reconnect_initial_backoff: Duration,
    pub reconnect_max_backoff: Duration,
    pub reconnect_max_retries: u32,
}

impl Default for ClientConfig_ {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(150),
            keep_alive_interval: Duration::from_secs(30),
            reconnect_initial_backoff: Duration::from_secs(1),
            reconnect_max_backoff: Duration::from_secs(60),
            reconnect_max_retries: 5,
        }
    }
}

struct ReconnectState {
    attempts: u32,
    next_retry_at: Instant,
}

pub struct StreamingResponse {
    recv: quinn::RecvStream,
}

impl StreamingResponse {
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        match read_frame(&mut self.recv).await {
            Ok((MessageType::StreamChunk, payload)) => {
                let chunk: StreamChunk = rmp_serde::from_slice(&payload).map_err(|e| {
                    LightningError::Serialization(format!("Failed to parse stream chunk: {}", e))
                })?;
                Ok(Some(chunk.data))
            }
            Ok((MessageType::StreamEnd, payload)) => {
                let end: StreamEnd = rmp_serde::from_slice(&payload).map_err(|e| {
                    LightningError::Serialization(format!("Failed to parse stream end: {}", e))
                })?;
                if end.success {
                    Ok(None)
                } else {
                    Err(LightningError::Stream(end.error.unwrap_or_default()))
                }
            }
            Ok((MessageType::SynapseResponse, payload)) => {
                let detail = rmp_serde::from_slice::<SynapseResponse>(&payload)
                    .ok()
                    .and_then(|r| r.error)
                    .unwrap_or_else(|| "no detail".to_string());
                Err(LightningError::Stream(format!(
                    "server returned SynapseResponse error on streaming path: {}",
                    detail
                )))
            }
            Ok((msg_type, _)) => Err(LightningError::Stream(format!(
                "unexpected message type during streaming: {:?}",
                msg_type
            ))),
            Err(e) => Err(e),
        }
    }

    pub async fn collect_all(&mut self) -> Result<Vec<Vec<u8>>> {
        let mut chunks = Vec::new();
        let mut total_size: usize = 0;
        while let Some(chunk) = self.next_chunk().await? {
            total_size += chunk.len();
            if total_size > MAX_RESPONSE_SIZE {
                return Err(LightningError::Stream(format!(
                    "streaming response exceeded {} byte limit",
                    MAX_RESPONSE_SIZE
                )));
            }
            chunks.push(chunk);
        }
        Ok(chunks)
    }
}

pub struct LightningClient {
    config: ClientConfig_,
    wallet_hotkey: String,
    signer: Option<Arc<dyn Signer>>,
    connection_pool: Arc<RwLock<ConnectionPool>>,
    active_miners: Arc<RwLock<HashMap<String, QuicAxonInfo>>>,
    established_connections: Arc<RwLock<HashMap<String, Connection>>>,
    reconnect_states: Arc<RwLock<HashMap<String, ReconnectState>>>,
    endpoint: Option<Endpoint>,
}

impl LightningClient {
    pub fn new(wallet_hotkey: String) -> Self {
        Self::with_config(wallet_hotkey, ClientConfig_::default())
    }

    pub fn with_config(wallet_hotkey: String, config: ClientConfig_) -> Self {
        Self {
            config,
            wallet_hotkey,
            signer: None,
            connection_pool: Arc::new(RwLock::new(ConnectionPool::new())),
            active_miners: Arc::new(RwLock::new(HashMap::new())),
            established_connections: Arc::new(RwLock::new(HashMap::new())),
            reconnect_states: Arc::new(RwLock::new(HashMap::new())),
            endpoint: None,
        }
    }

    pub fn set_signer(&mut self, signer: Box<dyn Signer>) {
        self.signer = Some(Arc::from(signer));
        info!("Signer configured");
    }

    #[cfg(feature = "btwallet")]
    pub fn set_wallet(
        &mut self,
        wallet_name: &str,
        wallet_path: &str,
        hotkey_name: &str,
    ) -> Result<()> {
        let signer =
            crate::signing::BtWalletSigner::from_wallet(wallet_name, wallet_path, hotkey_name)?;
        self.set_signer(Box::new(signer));
        Ok(())
    }

    pub async fn initialize_connections(&mut self, miners: Vec<QuicAxonInfo>) -> Result<()> {
        self.create_endpoint().await?;

        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or_else(|| LightningError::Connection("QUIC endpoint not initialized".into()))?
            .clone();
        let wallet_hotkey = self.wallet_hotkey.clone();
        let signer = self
            .signer
            .as_ref()
            .ok_or_else(|| LightningError::Signing("No signer configured".into()))?
            .clone();
        let timeout = self.config.connect_timeout;

        let mut set = tokio::task::JoinSet::new();
        for miner in miners {
            let ep = endpoint.clone();
            let wh = wallet_hotkey.clone();
            let s = signer.clone();
            set.spawn(async move {
                let miner_key = format!("{}:{}", miner.ip, miner.port);
                let result =
                    tokio::time::timeout(timeout, connect_and_handshake(ep, miner.clone(), wh, s))
                        .await;
                let result = match result {
                    Ok(r) => r,
                    Err(_) => Err(LightningError::Connection(format!(
                        "Connection to {} timed out",
                        miner_key
                    ))),
                };
                (miner_key, miner, result)
            });
        }

        let mut active_miners = self.active_miners.write().await;
        let mut pool = self.connection_pool.write().await;
        let mut connections = self.established_connections.write().await;

        while let Some(join_result) = set.join_next().await {
            match join_result {
                Ok((miner_key, miner, result)) => match result {
                    Ok(connection) => {
                        let connection_id =
                            format!("{}:{}:{}", miner.ip, miner.port, unix_timestamp_millis());
                        pool.add_connection(&miner_key, connection_id);
                        active_miners.insert(miner_key.clone(), miner);
                        info!(
                            "Established persistent QUIC connection to miner: {}",
                            miner_key
                        );
                        connections.insert(miner_key, connection);
                    }
                    Err(e) => {
                        error!("Failed to connect to miner {}: {}", miner_key, e);
                    }
                },
                Err(e) => {
                    error!("Connection task panicked: {}", e);
                }
            }
        }

        Ok(())
    }

    pub async fn create_endpoint(&mut self) -> Result<()> {
        let mut tls_config = RustlsClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertVerifier))
            .with_no_client_auth();

        tls_config.alpn_protocols = vec![b"btlightning".to_vec()];

        let mut transport_config = TransportConfig::default();

        let idle_timeout = IdleTimeout::try_from(self.config.idle_timeout)
            .map_err(|e| LightningError::Config(format!("Failed to set idle timeout: {}", e)))?;
        transport_config.max_idle_timeout(Some(idle_timeout));
        transport_config.keep_alive_interval(Some(self.config.keep_alive_interval));

        let mut client_config = ClientConfig::new(Arc::new(tls_config));
        client_config.transport_config(Arc::new(transport_config));

        let bind_addr: SocketAddr = "0.0.0.0:0"
            .parse()
            .map_err(|e| LightningError::Config(format!("Failed to parse bind address: {}", e)))?;
        let mut endpoint = Endpoint::client(bind_addr).map_err(|e| {
            LightningError::Connection(format!("Failed to create QUIC endpoint: {}", e))
        })?;
        endpoint.set_default_client_config(client_config);
        self.endpoint = Some(endpoint);

        info!("QUIC client endpoint created");
        Ok(())
    }

    pub async fn query_axon(
        &self,
        axon_info: QuicAxonInfo,
        request: QuicRequest,
    ) -> Result<QuicResponse> {
        let miner_key = format!("{}:{}", axon_info.ip, axon_info.port);

        let connection = {
            let connections = self.established_connections.read().await;
            connections.get(&miner_key).cloned()
        };

        match connection {
            Some(conn) if conn.close_reason().is_none() => {
                send_synapse_packet(&conn, request).await
            }
            _ => {
                self.try_reconnect_and_query(&miner_key, &axon_info, request)
                    .await
            }
        }
    }

    pub async fn query_axon_stream(
        &self,
        axon_info: QuicAxonInfo,
        request: QuicRequest,
    ) -> Result<StreamingResponse> {
        let miner_key = format!("{}:{}", axon_info.ip, axon_info.port);

        let connection = {
            let connections = self.established_connections.read().await;
            connections.get(&miner_key).cloned()
        };

        match connection {
            Some(conn) if conn.close_reason().is_none() => {
                open_streaming_synapse(&conn, request).await
            }
            _ => {
                self.try_reconnect_and_stream(&miner_key, &axon_info, request)
                    .await
            }
        }
    }

    async fn try_reconnect_and_query(
        &self,
        miner_key: &str,
        axon_info: &QuicAxonInfo,
        request: QuicRequest,
    ) -> Result<QuicResponse> {
        let connection = self.try_reconnect(miner_key, axon_info).await?;
        send_synapse_packet(&connection, request).await
    }

    async fn try_reconnect_and_stream(
        &self,
        miner_key: &str,
        axon_info: &QuicAxonInfo,
        request: QuicRequest,
    ) -> Result<StreamingResponse> {
        let connection = self.try_reconnect(miner_key, axon_info).await?;
        open_streaming_synapse(&connection, request).await
    }

    async fn try_reconnect(&self, miner_key: &str, axon_info: &QuicAxonInfo) -> Result<Connection> {
        {
            let states = self.reconnect_states.read().await;
            if let Some(state) = states.get(miner_key) {
                if state.attempts >= self.config.reconnect_max_retries {
                    return Err(LightningError::Connection(format!(
                        "Reconnection attempts exhausted for {} ({}/{}), awaiting registry refresh",
                        miner_key, state.attempts, self.config.reconnect_max_retries
                    )));
                }
                if Instant::now() < state.next_retry_at {
                    return Err(LightningError::Connection(format!(
                        "Reconnection to {} in backoff, next retry in {:?}",
                        miner_key,
                        state.next_retry_at - Instant::now()
                    )));
                }
            }
        }

        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or_else(|| LightningError::Connection("QUIC endpoint not initialized".into()))?
            .clone();
        let signer = self
            .signer
            .as_ref()
            .ok_or_else(|| LightningError::Signing("No signer configured".into()))?
            .clone();

        warn!("Connection to {} dead, attempting reconnection", miner_key);

        let reconnect_result = tokio::time::timeout(
            self.config.connect_timeout,
            connect_and_handshake(
                endpoint,
                axon_info.clone(),
                self.wallet_hotkey.clone(),
                signer,
            ),
        )
        .await;

        let reconnect_result = match reconnect_result {
            Ok(r) => r,
            Err(_) => Err(LightningError::Connection(format!(
                "Reconnection to {} timed out",
                miner_key
            ))),
        };

        match reconnect_result {
            Ok(connection) => {
                {
                    let mut connections = self.established_connections.write().await;
                    connections.insert(miner_key.to_string(), connection.clone());
                }
                {
                    let mut states = self.reconnect_states.write().await;
                    states.remove(miner_key);
                }
                info!("Reconnected to miner {}", miner_key);
                Ok(connection)
            }
            Err(e) => {
                let mut states = self.reconnect_states.write().await;
                let state = states
                    .entry(miner_key.to_string())
                    .or_insert_with(|| ReconnectState {
                        attempts: 0,
                        next_retry_at: Instant::now(),
                    });
                state.attempts += 1;
                let shift = state.attempts.min(20);
                let backoff = (self.config.reconnect_initial_backoff * 2u32.pow(shift))
                    .min(self.config.reconnect_max_backoff);
                state.next_retry_at = Instant::now() + backoff;
                error!(
                    "Reconnection to {} failed (attempt {}/{}), next retry in {:?}: {}",
                    miner_key, state.attempts, self.config.reconnect_max_retries, backoff, e
                );
                Err(e)
            }
        }
    }

    pub async fn update_miner_registry(&self, miners: Vec<QuicAxonInfo>) -> Result<()> {
        let current_miners: HashMap<String, QuicAxonInfo> = miners
            .iter()
            .map(|m| (format!("{}:{}", m.ip, m.port), m.clone()))
            .collect();

        let new_miner_keys: Vec<(String, QuicAxonInfo)>;
        {
            let mut active_miners = self.active_miners.write().await;
            let mut pool = self.connection_pool.write().await;
            let mut connections = self.established_connections.write().await;
            let mut reconnect_states = self.reconnect_states.write().await;

            let active_keys: Vec<String> = active_miners.keys().cloned().collect();
            for key in active_keys {
                if !current_miners.contains_key(&key) {
                    info!("Miner deregistered, closing QUIC connection: {}", key);
                    if let Some(connection) = connections.remove(&key) {
                        connection.close(0u32.into(), b"miner_deregistered");
                    }
                    pool.remove_connection(&key);
                    active_miners.remove(&key);
                    reconnect_states.remove(&key);
                }
            }

            for key in current_miners.keys() {
                if reconnect_states.remove(key).is_some() {
                    info!("Registry refresh reset reconnection backoff for {}", key);
                }
            }

            new_miner_keys = current_miners
                .into_iter()
                .filter(|(key, _)| !active_miners.contains_key(key))
                .collect();
        }

        if !new_miner_keys.is_empty() {
            let endpoint = self
                .endpoint
                .as_ref()
                .ok_or_else(|| LightningError::Connection("QUIC endpoint not initialized".into()))?
                .clone();
            let wallet_hotkey = self.wallet_hotkey.clone();
            let signer = self
                .signer
                .as_ref()
                .ok_or_else(|| LightningError::Signing("No signer configured".into()))?
                .clone();
            let timeout = self.config.connect_timeout;

            let mut set = tokio::task::JoinSet::new();
            for (key, miner) in new_miner_keys {
                info!("New miner detected, establishing QUIC connection: {}", key);
                let ep = endpoint.clone();
                let wh = wallet_hotkey.clone();
                let s = signer.clone();
                set.spawn(async move {
                    let result = tokio::time::timeout(
                        timeout,
                        connect_and_handshake(ep, miner.clone(), wh, s),
                    )
                    .await;
                    let result = match result {
                        Ok(r) => r,
                        Err(_) => Err(LightningError::Connection(format!(
                            "Connection to {} timed out",
                            key
                        ))),
                    };
                    (key, miner, result)
                });
            }

            let mut active_miners = self.active_miners.write().await;
            let mut pool = self.connection_pool.write().await;
            let mut connections = self.established_connections.write().await;

            while let Some(join_result) = set.join_next().await {
                match join_result {
                    Ok((key, miner, result)) => match result {
                        Ok(connection) => {
                            if active_miners.contains_key(&key) {
                                connection.close(0u32.into(), b"duplicate");
                            } else {
                                let connection_id = format!(
                                    "{}:{}:{}",
                                    miner.ip,
                                    miner.port,
                                    unix_timestamp_millis()
                                );
                                pool.add_connection(&key, connection_id);
                                active_miners.insert(key.clone(), miner);
                                connections.insert(key, connection);
                            }
                        }
                        Err(e) => {
                            error!("Failed to connect to new miner {}: {}", key, e);
                        }
                    },
                    Err(e) => {
                        error!("Connection task panicked: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn get_connection_stats(&self) -> Result<HashMap<String, String>> {
        let pool = self.connection_pool.read().await;
        let active_miners = self.active_miners.read().await;
        let connections = self.established_connections.read().await;

        let mut stats = HashMap::new();
        stats.insert(
            "total_connections".to_string(),
            pool.connection_count().to_string(),
        );
        stats.insert("active_miners".to_string(), active_miners.len().to_string());
        stats.insert(
            "quic_connections".to_string(),
            connections.len().to_string(),
        );

        for (key, _) in active_miners.iter() {
            if let Some(connection_id) = pool.get_connection(key) {
                stats.insert(format!("connection_{}", key), connection_id);
            }
        }

        Ok(stats)
    }

    pub async fn close_all_connections(&self) -> Result<()> {
        let mut pool = self.connection_pool.write().await;
        let mut active_miners = self.active_miners.write().await;
        let mut connections = self.established_connections.write().await;
        let mut reconnect_states = self.reconnect_states.write().await;

        for (_, connection) in connections.drain() {
            connection.close(0u32.into(), b"client_shutdown");
        }

        pool.close_all();
        active_miners.clear();
        reconnect_states.clear();

        info!("All Lightning QUIC connections closed");
        Ok(())
    }
}

fn get_peer_cert_fingerprint(connection: &Connection) -> Option<[u8; 32]> {
    let identity = connection.peer_identity()?;
    let certs = identity.downcast::<Vec<rustls::Certificate>>().ok()?;
    let first = certs.first()?;
    Some(blake2_256(&first.0))
}

async fn connect_and_handshake(
    endpoint: Endpoint,
    miner: QuicAxonInfo,
    wallet_hotkey: String,
    signer: Arc<dyn Signer>,
) -> Result<Connection> {
    let addr: SocketAddr = format!("{}:{}", miner.ip, miner.port)
        .parse()
        .map_err(|e| LightningError::Connection(format!("Invalid address: {}", e)))?;

    let connection = endpoint
        .connect(addr, &miner.ip)
        .map_err(|e| LightningError::Connection(format!("Connection failed: {}", e)))?
        .await
        .map_err(|e| LightningError::Connection(format!("Connection handshake failed: {}", e)))?;

    let peer_cert_fp = get_peer_cert_fingerprint(&connection);
    let peer_cert_fp_b64 = peer_cert_fp
        .as_ref()
        .map(|fp| BASE64_STANDARD.encode(fp))
        .unwrap_or_default();

    let nonce = generate_nonce();
    let timestamp = unix_timestamp_secs();
    let message = format!(
        "handshake:{}:{}:{}:{}",
        wallet_hotkey, timestamp, nonce, peer_cert_fp_b64
    );
    let signature_bytes = signer.sign(message.as_bytes())?;

    let handshake_request = HandshakeRequest {
        validator_hotkey: wallet_hotkey.clone(),
        timestamp,
        nonce: nonce.clone(),
        signature: BASE64_STANDARD.encode(&signature_bytes),
    };

    let response = send_handshake(&connection, handshake_request).await?;
    if !response.accepted {
        return Err(LightningError::Handshake(
            "Handshake rejected by miner".into(),
        ));
    }

    if response.miner_hotkey != miner.hotkey {
        return Err(LightningError::Handshake(format!(
            "Miner hotkey mismatch: expected {}, got {}",
            miner.hotkey, response.miner_hotkey
        )));
    }

    if let Some(ref resp_fp) = response.cert_fingerprint {
        if *resp_fp != peer_cert_fp_b64 {
            return Err(LightningError::Handshake(
                "Cert fingerprint mismatch between TLS session and handshake response".to_string(),
            ));
        }
    }

    verify_miner_response_signature(&response, &wallet_hotkey, &nonce, &peer_cert_fp_b64).await?;

    info!("Handshake successful with miner {}", miner.hotkey);
    Ok(connection)
}

async fn verify_miner_response_signature(
    response: &HandshakeResponse,
    validator_hotkey: &str,
    nonce: &str,
    cert_fp_b64: &str,
) -> Result<()> {
    if response.signature.is_empty() {
        return Err(LightningError::Handshake(
            "Miner returned empty signature".to_string(),
        ));
    }

    let expected_message = format!(
        "handshake_response:{}:{}:{}:{}:{}",
        validator_hotkey, response.miner_hotkey, response.timestamp, nonce, cert_fp_b64
    );

    let public_key = sr25519::Public::from_ss58check(&response.miner_hotkey).map_err(|e| {
        LightningError::Handshake(format!(
            "Invalid miner SS58 address {}: {}",
            response.miner_hotkey, e
        ))
    })?;

    let signature_bytes = BASE64_STANDARD.decode(&response.signature).map_err(|e| {
        LightningError::Handshake(format!("Failed to decode miner signature: {}", e))
    })?;

    if signature_bytes.len() != 64 {
        return Err(LightningError::Handshake(format!(
            "Invalid miner signature length: {}",
            signature_bytes.len()
        )));
    }

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&signature_bytes);
    let signature = sr25519::Signature::from_raw(sig_array);

    let valid = tokio::task::spawn_blocking(move || {
        sr25519::Pair::verify(&signature, expected_message.as_bytes(), &public_key)
    })
    .await
    .map_err(|e| LightningError::Handshake(format!("signature verification task failed: {}", e)))?;

    if !valid {
        return Err(LightningError::Handshake(
            "Miner response signature verification failed".to_string(),
        ));
    }

    Ok(())
}

async fn send_handshake(
    connection: &Connection,
    request: HandshakeRequest,
) -> Result<HandshakeResponse> {
    let (mut send, mut recv) = connection.open_bi().await.map_err(|e| {
        LightningError::Connection(format!("Failed to open bidirectional stream: {}", e))
    })?;

    let request_bytes = rmp_serde::to_vec(&request).map_err(|e| {
        LightningError::Serialization(format!("Failed to serialize handshake: {}", e))
    })?;

    write_frame_and_finish(&mut send, MessageType::HandshakeRequest, &request_bytes).await?;

    let (msg_type, payload) = read_frame(&mut recv).await?;
    if msg_type != MessageType::HandshakeResponse {
        return Err(LightningError::Handshake(format!(
            "Expected HandshakeResponse, got {:?}",
            msg_type
        )));
    }

    let response: HandshakeResponse = rmp_serde::from_slice(&payload).map_err(|e| {
        LightningError::Serialization(format!("Failed to parse handshake response: {}", e))
    })?;

    Ok(response)
}

async fn send_synapse_frame(send: &mut quinn::SendStream, request: QuicRequest) -> Result<()> {
    let synapse_packet = SynapsePacket {
        synapse_type: request.synapse_type,
        data: request.data,
        timestamp: unix_timestamp_secs(),
    };

    let packet_bytes = rmp_serde::to_vec(&synapse_packet).map_err(|e| {
        LightningError::Serialization(format!("Failed to serialize synapse packet: {}", e))
    })?;

    write_frame_and_finish(send, MessageType::SynapsePacket, &packet_bytes).await
}

async fn send_synapse_packet(
    connection: &Connection,
    request: QuicRequest,
) -> Result<QuicResponse> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| LightningError::Connection(format!("Failed to open stream: {}", e)))?;

    let start = Instant::now();

    send_synapse_frame(&mut send, request).await?;

    let (msg_type, payload) = read_frame(&mut recv).await?;

    match msg_type {
        MessageType::SynapseResponse => {
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            let synapse_response: SynapseResponse =
                rmp_serde::from_slice(&payload).map_err(|e| {
                    LightningError::Serialization(format!(
                        "Failed to parse synapse response: {}",
                        e
                    ))
                })?;

            Ok(QuicResponse {
                success: synapse_response.success,
                data: synapse_response.data,
                latency_ms,
            })
        }
        MessageType::StreamChunk => {
            let first_chunk: StreamChunk = rmp_serde::from_slice(&payload).map_err(|e| {
                LightningError::Serialization(format!("Failed to parse stream chunk: {}", e))
            })?;

            let mut all_data = first_chunk.data;
            loop {
                let (frame_type, frame_payload) = read_frame(&mut recv).await?;
                match frame_type {
                    MessageType::StreamChunk => {
                        let chunk: StreamChunk =
                            rmp_serde::from_slice(&frame_payload).map_err(|e| {
                                LightningError::Serialization(format!(
                                    "Failed to parse stream chunk: {}",
                                    e
                                ))
                            })?;
                        if all_data.len() + chunk.data.len() > MAX_RESPONSE_SIZE {
                            return Err(LightningError::Stream(format!(
                                "streaming response exceeded {} byte limit",
                                MAX_RESPONSE_SIZE
                            )));
                        }
                        all_data.extend_from_slice(&chunk.data);
                    }
                    MessageType::StreamEnd => {
                        let end: StreamEnd =
                            rmp_serde::from_slice(&frame_payload).map_err(|e| {
                                LightningError::Serialization(format!(
                                    "Failed to parse stream end: {}",
                                    e
                                ))
                            })?;
                        if !end.success {
                            return Err(LightningError::Stream(end.error.unwrap_or_default()));
                        }
                        break;
                    }
                    other => {
                        return Err(LightningError::Stream(format!(
                            "unexpected frame type during streaming collection: {:?}",
                            other
                        )));
                    }
                }
            }

            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            let mut data = HashMap::new();
            data.insert("raw".to_string(), rmpv::Value::Binary(all_data));
            Ok(QuicResponse {
                success: true,
                data,
                latency_ms,
            })
        }
        other => Err(LightningError::Transport(format!(
            "unexpected response type: {:?}",
            other
        ))),
    }
}

async fn open_streaming_synapse(
    connection: &Connection,
    request: QuicRequest,
) -> Result<StreamingResponse> {
    let (mut send, recv) = connection
        .open_bi()
        .await
        .map_err(|e| LightningError::Connection(format!("Failed to open stream: {}", e)))?;

    send_synapse_frame(&mut send, request).await?;

    Ok(StreamingResponse { recv })
}

fn generate_nonce() -> String {
    use rand::Rng;
    let bytes: [u8; 16] = rand::thread_rng().gen();
    format!("{:032x}", u128::from_be_bytes(bytes))
}

struct AcceptAnyCertVerifier;

impl rustls::client::ServerCertVerifier for AcceptAnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}
