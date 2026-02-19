use crate::error::{LightningError, Result};
#[cfg(feature = "btwallet")]
use crate::signing::BtWalletSigner;
use crate::signing::{Signer, Sr25519Signer};
use crate::types::{
    handshake_request_message, handshake_response_message, hashmap_to_rmpv_map, read_frame,
    serialize_to_rmpv_map, write_frame, write_frame_and_finish, HandshakeRequest,
    HandshakeResponse, MessageType, StreamChunk, StreamEnd, SynapsePacket, SynapseResponse,
};
use crate::util::unix_timestamp_secs;
use base64::{prelude::BASE64_STANDARD, Engine};
use quinn::{
    Connection, Endpoint, IdleTimeout, RecvStream, SendStream, ServerConfig, TransportConfig,
};
use rustls::{Certificate, PrivateKey, ServerConfig as RustlsServerConfig};
use sp_core::{blake2_256, crypto::Ss58Codec, sr25519, Pair};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

#[derive(Debug, Copy, Clone)]
pub struct LightningServerConfig {
    pub max_signature_age_secs: u64,
    pub idle_timeout_secs: u64,
    pub keep_alive_interval_secs: u64,
    pub nonce_cleanup_interval_secs: u64,
    pub max_connections: usize,
}

impl Default for LightningServerConfig {
    fn default() -> Self {
        Self {
            max_signature_age_secs: 300,
            idle_timeout_secs: 150,
            keep_alive_interval_secs: 30,
            nonce_cleanup_interval_secs: 60,
            max_connections: 128,
        }
    }
}

pub trait SynapseHandler: Send + Sync {
    fn handle(
        &self,
        synapse_type: &str,
        data: HashMap<String, rmpv::Value>,
    ) -> Result<HashMap<String, rmpv::Value>>;
}

#[async_trait::async_trait]
pub trait AsyncSynapseHandler: Send + Sync {
    async fn handle(
        &self,
        synapse_type: &str,
        data: HashMap<String, rmpv::Value>,
    ) -> Result<HashMap<String, rmpv::Value>>;
}

#[async_trait::async_trait]
pub trait StreamingSynapseHandler: Send + Sync {
    async fn handle(
        &self,
        synapse_type: &str,
        data: HashMap<String, rmpv::Value>,
        sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> Result<()>;
}

#[derive(Debug)]
pub struct ValidatorConnection {
    pub validator_hotkey: String,
    pub connection_id: String,
    pub established_at: u64,
    pub last_activity: AtomicU64,
    pub verified: bool,
    pub connection: Arc<quinn::Connection>,
}

impl ValidatorConnection {
    pub fn new(
        validator_hotkey: String,
        connection_id: String,
        conn: Arc<quinn::Connection>,
    ) -> Self {
        let now = unix_timestamp_secs();
        Self {
            validator_hotkey,
            connection_id,
            established_at: now,
            last_activity: AtomicU64::new(now),
            verified: false,
            connection: conn,
        }
    }

    pub fn verify(&mut self) {
        self.verified = true;
        self.update_activity();
    }

    pub fn update_activity(&self) {
        self.last_activity
            .store(unix_timestamp_secs(), Ordering::Relaxed);
    }
}

#[derive(Clone)]
struct ServerContext {
    connections: Arc<RwLock<HashMap<String, ValidatorConnection>>>,
    addr_to_hotkey: Arc<RwLock<HashMap<SocketAddr, String>>>,
    synapse_handlers: Arc<RwLock<HashMap<String, Arc<dyn SynapseHandler>>>>,
    async_handlers: Arc<RwLock<HashMap<String, Arc<dyn AsyncSynapseHandler>>>>,
    streaming_handlers: Arc<RwLock<HashMap<String, Arc<dyn StreamingSynapseHandler>>>>,
    used_nonces: Arc<RwLock<HashMap<String, u64>>>,
    miner_hotkey: String,
    miner_signer: Option<Arc<dyn Signer>>,
    cert_fingerprint: Arc<RwLock<Option<[u8; 32]>>>,
    config: LightningServerConfig,
}

pub struct LightningServer {
    host: String,
    port: u16,
    ctx: ServerContext,
    endpoint: Option<Endpoint>,
    cleanup_handle: Arc<tokio::sync::Mutex<Option<JoinHandle<()>>>>,
}

impl LightningServer {
    pub fn new(miner_hotkey: String, host: String, port: u16) -> Result<Self> {
        Self::with_config(miner_hotkey, host, port, LightningServerConfig::default())
    }

    pub fn with_config(
        miner_hotkey: String,
        host: String,
        port: u16,
        config: LightningServerConfig,
    ) -> Result<Self> {
        if config.max_signature_age_secs == 0 {
            return Err(LightningError::Config(
                "max_signature_age_secs must be non-zero".to_string(),
            ));
        }
        if config.max_signature_age_secs > 3600 {
            return Err(LightningError::Config(
                "max_signature_age_secs must not exceed 3600 (1 hour)".to_string(),
            ));
        }
        if config.nonce_cleanup_interval_secs == 0 {
            return Err(LightningError::Config(
                "nonce_cleanup_interval_secs must be non-zero".to_string(),
            ));
        }
        if config.idle_timeout_secs == 0 {
            return Err(LightningError::Config(
                "idle_timeout_secs must be non-zero".to_string(),
            ));
        }
        if config.keep_alive_interval_secs == 0 {
            return Err(LightningError::Config(
                "keep_alive_interval_secs must be non-zero".to_string(),
            ));
        }
        if config.keep_alive_interval_secs >= config.idle_timeout_secs {
            return Err(LightningError::Config(format!(
                "keep_alive_interval_secs ({}) must be less than idle_timeout_secs ({})",
                config.keep_alive_interval_secs, config.idle_timeout_secs
            )));
        }
        if config.max_connections == 0 {
            return Err(LightningError::Config(
                "max_connections must be non-zero".to_string(),
            ));
        }
        Ok(Self {
            host,
            port,
            ctx: ServerContext {
                connections: Arc::new(RwLock::new(HashMap::new())),
                addr_to_hotkey: Arc::new(RwLock::new(HashMap::new())),
                synapse_handlers: Arc::new(RwLock::new(HashMap::new())),
                async_handlers: Arc::new(RwLock::new(HashMap::new())),
                streaming_handlers: Arc::new(RwLock::new(HashMap::new())),
                used_nonces: Arc::new(RwLock::new(HashMap::new())),
                miner_hotkey,
                miner_signer: None,
                cert_fingerprint: Arc::new(RwLock::new(None)),
                config,
            },
            endpoint: None,
            cleanup_handle: Arc::new(tokio::sync::Mutex::new(None)),
        })
    }

    pub fn set_miner_keypair(&mut self, keypair_bytes: [u8; 32]) {
        self.ctx.miner_signer = Some(Arc::new(Sr25519Signer::from_seed(keypair_bytes)));
    }

    pub fn set_miner_signer(&mut self, signer: Box<dyn Signer>) {
        self.ctx.miner_signer = Some(Arc::from(signer));
    }

    #[cfg(feature = "btwallet")]
    pub fn set_miner_wallet(
        &mut self,
        wallet_name: &str,
        wallet_path: &str,
        hotkey_name: &str,
    ) -> Result<()> {
        let signer = BtWalletSigner::from_wallet(wallet_name, wallet_path, hotkey_name)?;
        self.ctx.miner_signer = Some(Arc::new(signer));
        Ok(())
    }

    pub async fn register_synapse_handler(
        &self,
        synapse_type: String,
        handler: Arc<dyn SynapseHandler>,
    ) -> Result<()> {
        let mut handlers = self.ctx.synapse_handlers.write().await;
        handlers.insert(synapse_type.clone(), handler);
        info!("Registered synapse handler for: {}", synapse_type);
        Ok(())
    }

    pub async fn register_async_synapse_handler(
        &self,
        synapse_type: String,
        handler: Arc<dyn AsyncSynapseHandler>,
    ) -> Result<()> {
        let mut handlers = self.ctx.async_handlers.write().await;
        handlers.insert(synapse_type.clone(), handler);
        info!("Registered async synapse handler for: {}", synapse_type);
        Ok(())
    }

    pub async fn register_streaming_handler(
        &self,
        synapse_type: String,
        handler: Arc<dyn StreamingSynapseHandler>,
    ) -> Result<()> {
        let mut handlers = self.ctx.streaming_handlers.write().await;
        handlers.insert(synapse_type.clone(), handler);
        info!("Registered streaming synapse handler for: {}", synapse_type);
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn create_self_signed_cert(
    ) -> std::result::Result<(Vec<Certificate>, PrivateKey, [u8; 32]), Box<dyn std::error::Error>>
    {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let cert_der = cert.serialize_der()?;
        let priv_key = cert.serialize_private_key_der();
        let fingerprint = blake2_256(&cert_der);

        Ok((
            vec![Certificate(cert_der)],
            PrivateKey(priv_key),
            fingerprint,
        ))
    }

    pub async fn start(&mut self) -> Result<()> {
        info!(
            "Starting Lightning QUIC server on {}:{}",
            self.host, self.port
        );
        let (certs, key, fingerprint) = Self::create_self_signed_cert()
            .map_err(|e| LightningError::Config(format!("Failed to create certificate: {}", e)))?;

        *self.ctx.cert_fingerprint.write().await = Some(fingerprint);

        let mut server_config = RustlsServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| LightningError::Config(format!("Failed to configure TLS: {}", e)))?;

        server_config.alpn_protocols = vec![b"btlightning".to_vec()];
        let mut transport_config = TransportConfig::default();
        let idle_timeout = IdleTimeout::try_from(Duration::from_secs(
            self.ctx.config.idle_timeout_secs,
        ))
        .map_err(|e| LightningError::Config(format!("Failed to set idle timeout: {}", e)))?;
        transport_config.max_idle_timeout(Some(idle_timeout));
        transport_config.keep_alive_interval(Some(Duration::from_secs(
            self.ctx.config.keep_alive_interval_secs,
        )));

        let mut server_config = ServerConfig::with_crypto(Arc::new(server_config));
        server_config.transport_config(Arc::new(transport_config));
        let addr: SocketAddr = format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|e| LightningError::Config(format!("Invalid address: {}", e)))?;

        let endpoint = Endpoint::server(server_config, addr).map_err(|e| {
            LightningError::Config(format!("Failed to create QUIC endpoint: {}", e))
        })?;

        info!("QUIC endpoint created, listening on {}", addr);
        self.endpoint = Some(endpoint);

        Ok(())
    }

    pub async fn serve_forever(&self) -> Result<()> {
        let endpoint = self.endpoint.as_ref().ok_or_else(|| {
            LightningError::Config("server not started: call start() first".to_string())
        })?;
        {
            let mut guard = self.cleanup_handle.lock().await;
            if let Some(old) = guard.take() {
                old.abort();
            }
        }

        let nonces_for_cleanup = self.ctx.used_nonces.clone();
        let cleanup_interval_secs = self.ctx.config.nonce_cleanup_interval_secs;
        let max_sig_age = self.ctx.config.max_signature_age_secs;
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(cleanup_interval_secs));
            loop {
                interval.tick().await;
                let mut nonces = nonces_for_cleanup.write().await;
                let cutoff = unix_timestamp_secs().saturating_sub(max_sig_age);
                nonces.retain(|_, ts| *ts >= cutoff);
            }
        });
        *self.cleanup_handle.lock().await = Some(handle);

        while let Some(conn) = endpoint.accept().await {
            let ctx = self.ctx.clone();

            tokio::spawn(async move {
                match conn.await {
                    Ok(connection) => {
                        Self::handle_connection(connection, ctx).await;
                    }
                    Err(e) => {
                        error!("Connection failed: {}", e);
                    }
                }
            });
        }
        Ok(())
    }

    async fn handle_connection(connection: Connection, ctx: ServerContext) {
        let connection = Arc::new(connection);

        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    let conn = connection.clone();
                    let ctx = ctx.clone();

                    tokio::spawn(async move {
                        Self::handle_stream(send, recv, conn, ctx).await;
                    });
                }
                Err(e) => {
                    debug!("Connection ended: {}", e);
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
                    connections.remove(&hotkey);
                    addr_index.remove(&remote_addr);
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
                connections.remove(&hotkey);
                addr_index.retain(|_, v| v != &hotkey);
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
        let frame = match read_frame(&mut recv).await {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to read frame: {}", e);
                return;
            }
        };

        match frame {
            (MessageType::SynapsePacket, payload) => {
                let packet: SynapsePacket = match rmp_serde::from_slice(&payload) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Failed to parse synapse packet: {}", e);
                        let err_response = SynapseResponse {
                            success: false,
                            data: HashMap::new(),
                            timestamp: unix_timestamp_secs(),
                            error: Some(e.to_string()),
                        };
                        if let Ok(bytes) = rmp_serde::to_vec(&err_response) {
                            let _ = write_frame_and_finish(
                                &mut send,
                                MessageType::SynapseResponse,
                                &bytes,
                            )
                            .await;
                        }
                        return;
                    }
                };

                let is_streaming = {
                    let handlers = ctx.streaming_handlers.read().await;
                    handlers.contains_key(&packet.synapse_type)
                };

                if is_streaming {
                    Self::handle_streaming_synapse(send, packet, connection, &ctx).await;
                } else {
                    let response =
                        Self::process_synapse_packet(packet, connection.clone(), &ctx).await;
                    match rmp_serde::to_vec(&response) {
                        Ok(bytes) => {
                            let _ = write_frame_and_finish(
                                &mut send,
                                MessageType::SynapseResponse,
                                &bytes,
                            )
                            .await;
                        }
                        Err(e) => {
                            error!("Failed to serialize SynapseResponse: {}", e);
                            let fallback = SynapseResponse {
                                success: false,
                                data: HashMap::new(),
                                timestamp: unix_timestamp_secs(),
                                error: Some("internal serialization error".to_string()),
                            };
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
                let request: HandshakeRequest = match rmp_serde::from_slice(&payload) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("Failed to parse handshake request: {}", e);
                        let err_response = HandshakeResponse {
                            miner_hotkey: ctx.miner_hotkey,
                            timestamp: unix_timestamp_secs(),
                            signature: String::new(),
                            accepted: false,
                            connection_id: String::new(),
                            cert_fingerprint: None,
                        };
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

                let response = Self::process_handshake(request, connection.clone(), &ctx).await;
                match rmp_serde::to_vec(&response) {
                    Ok(bytes) => {
                        let _ = write_frame_and_finish(
                            &mut send,
                            MessageType::HandshakeResponse,
                            &bytes,
                        )
                        .await;
                    }
                    Err(e) => {
                        error!("Failed to serialize HandshakeResponse: {}", e);
                        let fallback = HandshakeResponse {
                            miner_hotkey: ctx.miner_hotkey.clone(),
                            timestamp: unix_timestamp_secs(),
                            signature: String::new(),
                            accepted: false,
                            connection_id: String::new(),
                            cert_fingerprint: None,
                        };
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
            }
        }
    }

    async fn verify_synapse_auth(
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
                    return Err(SynapseResponse {
                        success: false,
                        data: HashMap::new(),
                        timestamp: unix_timestamp_secs(),
                        error: Some("Unknown or unauthenticated validator".to_string()),
                    });
                }
            }
        };

        {
            let connections_guard = ctx.connections.read().await;
            if let Some(conn) = connections_guard.get(&validator_hotkey) {
                if !conn.verified {
                    error!(
                        "Connection not verified for validator: {}",
                        validator_hotkey
                    );
                    return Err(SynapseResponse {
                        success: false,
                        data: HashMap::new(),
                        timestamp: unix_timestamp_secs(),
                        error: Some("Connection not verified".to_string()),
                    });
                }
                conn.update_activity();
            } else {
                error!("No connection found for validator {}", validator_hotkey);
                return Err(SynapseResponse {
                    success: false,
                    data: HashMap::new(),
                    timestamp: unix_timestamp_secs(),
                    error: Some("Unknown or unauthenticated validator".to_string()),
                });
            }
        }

        Ok(validator_hotkey)
    }

    async fn handle_streaming_synapse(
        mut send: SendStream,
        packet: SynapsePacket,
        connection: Arc<quinn::Connection>,
        ctx: &ServerContext,
    ) {
        if let Err(err_response) = Self::verify_synapse_auth(&connection, ctx).await {
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
                    let end = StreamEnd {
                        success: false,
                        error: Some(format!(
                            "No handler for synapse type: {}",
                            packet.synapse_type
                        )),
                    };
                    if let Ok(bytes) = rmp_serde::to_vec(&end) {
                        let _ =
                            write_frame_and_finish(&mut send, MessageType::StreamEnd, &bytes).await;
                    }
                    return;
                }
            }
        };

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        let synapse_type = packet.synapse_type.clone();

        let handle =
            tokio::spawn(async move { handler.handle(&synapse_type, packet.data, tx).await });

        while let Some(chunk_data) = rx.recv().await {
            let chunk = StreamChunk { data: chunk_data };
            match rmp_serde::to_vec(&chunk) {
                Ok(bytes) => {
                    if let Err(e) = write_frame(&mut send, MessageType::StreamChunk, &bytes).await {
                        error!("Failed to write stream chunk: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to serialize stream chunk: {}", e);
                    break;
                }
            }
        }

        let end = match handle.await {
            Ok(Ok(())) => StreamEnd {
                success: true,
                error: None,
            },
            Ok(Err(e)) => StreamEnd {
                success: false,
                error: Some(e.to_string()),
            },
            Err(e) => StreamEnd {
                success: false,
                error: Some(format!("handler panicked: {}", e)),
            },
        };

        if let Ok(bytes) = rmp_serde::to_vec(&end) {
            let _ = write_frame_and_finish(&mut send, MessageType::StreamEnd, &bytes).await;
        }
    }

    async fn process_handshake(
        request: HandshakeRequest,
        connection: Arc<quinn::Connection>,
        ctx: &ServerContext,
    ) -> HandshakeResponse {
        let cert_fp: Option<[u8; 32]> = *ctx.cert_fingerprint.read().await;
        let is_valid = Self::verify_validator_signature(
            &request,
            ctx.used_nonces.clone(),
            &cert_fp,
            ctx.config.max_signature_age_secs,
        )
        .await;

        if !is_valid {
            error!("Handshake failed: invalid signature");
            return HandshakeResponse {
                miner_hotkey: ctx.miner_hotkey.clone(),
                timestamp: unix_timestamp_secs(),
                signature: String::new(),
                accepted: false,
                connection_id: String::new(),
                cert_fingerprint: None,
            };
        }

        let now = unix_timestamp_secs();
        let signature = match Self::sign_handshake_response(
            &request,
            &ctx.miner_hotkey,
            ctx.miner_signer.as_deref(),
            now,
            &cert_fp,
        ) {
            Ok(sig) => sig,
            Err(e) => {
                error!("Handshake signing failed: {}", e);
                return HandshakeResponse {
                    miner_hotkey: ctx.miner_hotkey.clone(),
                    timestamp: now,
                    signature: String::new(),
                    accepted: false,
                    connection_id: String::new(),
                    cert_fingerprint: None,
                };
            }
        };

        let connection_id = format!(
            "conn_{}_{}",
            request.validator_hotkey,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_millis()
        );

        let remote_addr = connection.remote_address();
        let mut connections_guard = ctx.connections.write().await;
        let is_reconnect = connections_guard.contains_key(&request.validator_hotkey);
        if !is_reconnect && connections_guard.len() >= ctx.config.max_connections {
            error!(
                "Connection limit reached ({}/{}), rejecting validator {}",
                connections_guard.len(),
                ctx.config.max_connections,
                request.validator_hotkey
            );
            return HandshakeResponse {
                miner_hotkey: ctx.miner_hotkey.clone(),
                timestamp: now,
                signature: String::new(),
                accepted: false,
                connection_id: String::new(),
                cert_fingerprint: None,
            };
        }
        let mut addr_index = ctx.addr_to_hotkey.write().await;
        let mut validator_conn = ValidatorConnection::new(
            request.validator_hotkey.clone(),
            connection_id.clone(),
            connection.clone(),
        );
        validator_conn.verify();
        if let Some(prev_conn) =
            connections_guard.insert(request.validator_hotkey.clone(), validator_conn)
        {
            if !Arc::ptr_eq(&prev_conn.connection, &connection) {
                prev_conn.connection.close(0u32.into(), b"replaced");
                let prev_addr = prev_conn.connection.remote_address();
                if prev_addr != remote_addr {
                    addr_index.remove(&prev_addr);
                }
            }
        }
        addr_index.insert(remote_addr, request.validator_hotkey.clone());
        drop(addr_index);
        drop(connections_guard);

        info!(
            "Handshake successful, established connection: {}",
            connection_id
        );

        HandshakeResponse {
            miner_hotkey: ctx.miner_hotkey.clone(),
            timestamp: now,
            signature,
            accepted: true,
            connection_id,
            cert_fingerprint: cert_fp.map(|fp| BASE64_STANDARD.encode(fp)),
        }
    }

    async fn verify_validator_signature(
        request: &HandshakeRequest,
        used_nonces: Arc<RwLock<HashMap<String, u64>>>,
        cert_fingerprint: &Option<[u8; 32]>,
        max_signature_age: u64,
    ) -> bool {
        let current_time = unix_timestamp_secs();

        if current_time > request.timestamp
            && (current_time - request.timestamp) >= max_signature_age
        {
            error!(
                "Signature timestamp too old: {} (current: {})",
                request.timestamp, current_time
            );
            return false;
        }

        if request.timestamp > current_time + 60 {
            error!(
                "Signature timestamp too far in future: {} (current: {})",
                request.timestamp, current_time
            );
            return false;
        }

        let fp_b64 = cert_fingerprint
            .as_ref()
            .map(|fp| BASE64_STANDARD.encode(fp))
            .unwrap_or_default();
        let expected_message = handshake_request_message(
            &request.validator_hotkey,
            request.timestamp,
            &request.nonce,
            &fp_b64,
        );

        let public_key = match sr25519::Public::from_ss58check(&request.validator_hotkey) {
            Ok(pk) => pk,
            Err(e) => {
                error!("Invalid SS58 address {}: {}", request.validator_hotkey, e);
                return false;
            }
        };

        let signature_bytes = match BASE64_STANDARD.decode(&request.signature) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to decode base64 signature: {}", e);
                return false;
            }
        };

        if signature_bytes.len() != 64 {
            error!("Invalid signature length: {}", signature_bytes.len());
            return false;
        }

        let mut signature_array = [0u8; 64];
        signature_array.copy_from_slice(&signature_bytes);
        let signature = sr25519::Signature::from_raw(signature_array);

        let valid = match tokio::task::spawn_blocking(move || {
            sr25519::Pair::verify(&signature, expected_message.as_bytes(), &public_key)
        })
        .await
        {
            Ok(v) => v,
            Err(e) => {
                error!("signature verification task failed: {}", e);
                return false;
            }
        };

        if valid {
            let mut nonces = used_nonces.write().await;
            if nonces.contains_key(&request.nonce) {
                error!("Nonce already used: {}", request.nonce);
                return false;
            }
            nonces.insert(request.nonce.clone(), current_time);
        }

        valid
    }

    fn sign_handshake_response(
        request: &HandshakeRequest,
        miner_hotkey: &str,
        miner_signer: Option<&dyn Signer>,
        timestamp: u64,
        cert_fingerprint: &Option<[u8; 32]>,
    ) -> Result<String> {
        let signer = miner_signer
            .ok_or_else(|| LightningError::Signing("no miner signer configured".to_string()))?;
        let fp_b64 = cert_fingerprint
            .as_ref()
            .map(|fp| BASE64_STANDARD.encode(fp))
            .unwrap_or_default();
        let message = handshake_response_message(
            &request.validator_hotkey,
            miner_hotkey,
            timestamp,
            &request.nonce,
            &fp_b64,
        );
        let sig = signer.sign(message.as_bytes())?;
        Ok(BASE64_STANDARD.encode(sig))
    }

    async fn process_synapse_packet(
        packet: SynapsePacket,
        connection: Arc<quinn::Connection>,
        ctx: &ServerContext,
    ) -> SynapseResponse {
        let validator_hotkey = match Self::verify_synapse_auth(&connection, ctx).await {
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
                    SynapseResponse {
                        success: false,
                        data: HashMap::new(),
                        timestamp: unix_timestamp_secs(),
                        error: Some(e.to_string()),
                    }
                }
            }
        } else {
            drop(async_handlers);
            let handlers = ctx.synapse_handlers.read().await;
            if let Some(handler) = handlers.get(&packet.synapse_type).cloned() {
                drop(handlers);
                match handler.handle(&packet.synapse_type, packet.data) {
                    Ok(response_data) => SynapseResponse {
                        success: true,
                        data: response_data,
                        timestamp: unix_timestamp_secs(),
                        error: None,
                    },
                    Err(e) => {
                        error!("Handler error for {}: {}", packet.synapse_type, e);
                        SynapseResponse {
                            success: false,
                            data: HashMap::new(),
                            timestamp: unix_timestamp_secs(),
                            error: Some(e.to_string()),
                        }
                    }
                }
            } else {
                error!(
                    "No handler registered for synapse type: {}",
                    packet.synapse_type
                );
                SynapseResponse {
                    success: false,
                    data: HashMap::new(),
                    timestamp: unix_timestamp_secs(),
                    error: Some(format!(
                        "No handler for synapse type: {}",
                        packet.synapse_type
                    )),
                }
            }
        }
    }

    pub async fn get_connection_stats(&self) -> Result<HashMap<String, String>> {
        let connections = self.ctx.connections.read().await;
        let mut stats = HashMap::new();

        stats.insert(
            "total_connections".to_string(),
            connections.len().to_string(),
        );
        stats.insert(
            "verified_connections".to_string(),
            connections
                .values()
                .filter(|c| c.verified)
                .count()
                .to_string(),
        );

        for (validator, connection) in connections.iter() {
            if connection.verified {
                stats.insert(
                    format!("connection_{}", validator),
                    connection.connection_id.clone(),
                );
            }
        }

        Ok(stats)
    }

    pub async fn cleanup_stale_connections(&self, max_idle_seconds: u64) -> Result<()> {
        let mut connections = self.ctx.connections.write().await;
        let now = unix_timestamp_secs();

        let mut to_remove = Vec::new();
        for (validator, connection) in connections.iter() {
            if now.saturating_sub(connection.last_activity.load(Ordering::Relaxed))
                > max_idle_seconds
            {
                to_remove.push((validator.clone(), connection.connection.remote_address()));
            }
        }

        let mut addr_index = self.ctx.addr_to_hotkey.write().await;
        for (validator, remote_addr) in &to_remove {
            if let Some(connection) = connections.remove(validator) {
                connection.connection.close(0u32.into(), b"cleanup");
                info!("Cleaned up stale connection from validator: {}", validator);
            }
            addr_index.remove(remote_addr);
        }

        Ok(())
    }

    pub async fn cleanup_expired_nonces(&self) {
        let mut nonces = self.ctx.used_nonces.write().await;
        let cutoff = unix_timestamp_secs().saturating_sub(self.ctx.config.max_signature_age_secs);
        nonces.retain(|_, ts| *ts >= cutoff);
    }

    pub async fn stop(&self) -> Result<()> {
        if let Some(handle) = self.cleanup_handle.lock().await.take() {
            handle.abort();
        }

        let mut connections = self.ctx.connections.write().await;
        let mut addr_index = self.ctx.addr_to_hotkey.write().await;
        for (_, connection) in connections.drain() {
            connection.connection.close(0u32.into(), b"server_shutdown");
        }
        addr_index.clear();

        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0u32.into(), b"server_shutdown");
        }

        info!("Lightning QUIC server stopped, all connections closed");
        Ok(())
    }
}

/// Best-effort cleanup: aborts the nonce cleanup task if the mutex is not
/// held. Callers must invoke `stop()` for a guaranteed graceful shutdown
/// that closes all QUIC connections and the endpoint.
impl Drop for LightningServer {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.cleanup_handle.try_lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
    }
}

struct TypedSyncHandler<F, Req, Resp, E> {
    f: F,
    _phantom: std::marker::PhantomData<fn(Req) -> (Resp, E)>,
}

impl<F, Req, Resp, E> SynapseHandler for TypedSyncHandler<F, Req, Resp, E>
where
    Req: serde::de::DeserializeOwned + Send + 'static,
    Resp: serde::Serialize + Send + 'static,
    E: std::fmt::Display + 'static,
    F: Fn(Req) -> std::result::Result<Resp, E> + Send + Sync + 'static,
{
    fn handle(
        &self,
        _synapse_type: &str,
        data: HashMap<String, rmpv::Value>,
    ) -> Result<HashMap<String, rmpv::Value>> {
        let req: Req = rmpv::ext::from_value(hashmap_to_rmpv_map(data))
            .map_err(|e| LightningError::Serialization(e.to_string()))?;
        let resp = (self.f)(req).map_err(|e| LightningError::Handler(e.to_string()))?;
        serialize_to_rmpv_map(&resp)
    }
}

pub fn typed_handler<Req, Resp, E, F>(f: F) -> Arc<dyn SynapseHandler>
where
    Req: serde::de::DeserializeOwned + Send + 'static,
    Resp: serde::Serialize + Send + 'static,
    E: std::fmt::Display + 'static,
    F: Fn(Req) -> std::result::Result<Resp, E> + Send + Sync + 'static,
{
    Arc::new(TypedSyncHandler {
        f,
        _phantom: std::marker::PhantomData,
    })
}

#[allow(clippy::type_complexity)]
struct TypedAsyncHandler<F, Req, Resp, E, Fut> {
    f: F,
    _phantom: std::marker::PhantomData<fn(Req) -> (Resp, E, Fut)>,
}

#[async_trait::async_trait]
impl<F, Req, Resp, E, Fut> AsyncSynapseHandler for TypedAsyncHandler<F, Req, Resp, E, Fut>
where
    Req: serde::de::DeserializeOwned + Send + 'static,
    Resp: serde::Serialize + Send + 'static,
    E: std::fmt::Display + 'static,
    F: Fn(Req) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = std::result::Result<Resp, E>> + Send + 'static,
{
    async fn handle(
        &self,
        _synapse_type: &str,
        data: HashMap<String, rmpv::Value>,
    ) -> Result<HashMap<String, rmpv::Value>> {
        let req: Req = rmpv::ext::from_value(hashmap_to_rmpv_map(data))
            .map_err(|e| LightningError::Serialization(e.to_string()))?;
        let resp = (self.f)(req)
            .await
            .map_err(|e| LightningError::Handler(e.to_string()))?;
        serialize_to_rmpv_map(&resp)
    }
}

pub fn typed_async_handler<Req, Resp, E, F, Fut>(f: F) -> Arc<dyn AsyncSynapseHandler>
where
    Req: serde::de::DeserializeOwned + Send + 'static,
    Resp: serde::Serialize + Send + 'static,
    E: std::fmt::Display + 'static,
    F: Fn(Req) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = std::result::Result<Resp, E>> + Send + 'static,
{
    Arc::new(TypedAsyncHandler {
        f,
        _phantom: std::marker::PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_rejects_keepalive_ge_idle_timeout() {
        let config = LightningServerConfig {
            keep_alive_interval_secs: 150,
            idle_timeout_secs: 150,
            ..Default::default()
        };
        let result = LightningServer::with_config("test".into(), "0.0.0.0".into(), 8443, config);
        assert!(result.is_err());

        let config = LightningServerConfig {
            keep_alive_interval_secs: 200,
            idle_timeout_secs: 150,
            ..Default::default()
        };
        let result = LightningServer::with_config("test".into(), "0.0.0.0".into(), 8443, config);
        assert!(result.is_err());
    }

    #[test]
    fn config_accepts_keepalive_lt_idle_timeout() {
        let config = LightningServerConfig {
            keep_alive_interval_secs: 30,
            idle_timeout_secs: 150,
            ..Default::default()
        };
        let result = LightningServer::with_config("test".into(), "0.0.0.0".into(), 8443, config);
        assert!(result.is_ok());
    }

    #[test]
    fn config_rejects_zero_max_signature_age() {
        let config = LightningServerConfig {
            max_signature_age_secs: 0,
            ..Default::default()
        };
        let result = LightningServer::with_config("test".into(), "0.0.0.0".into(), 8443, config);
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_zero_nonce_cleanup_interval() {
        let config = LightningServerConfig {
            nonce_cleanup_interval_secs: 0,
            ..Default::default()
        };
        let result = LightningServer::with_config("test".into(), "0.0.0.0".into(), 8443, config);
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_zero_keepalive_interval() {
        let config = LightningServerConfig {
            keep_alive_interval_secs: 0,
            ..Default::default()
        };
        let result = LightningServer::with_config("test".into(), "0.0.0.0".into(), 8443, config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn verify_rejects_exact_boundary_timestamp() {
        let max_signature_age: u64 = 300;
        let now = unix_timestamp_secs();
        let request = HandshakeRequest {
            validator_hotkey: String::new(),
            timestamp: now.saturating_sub(max_signature_age),
            nonce: "test-nonce".to_string(),
            signature: String::new(),
        };
        let nonces = Arc::new(RwLock::new(HashMap::new()));
        let result =
            LightningServer::verify_validator_signature(&request, nonces, &None, max_signature_age)
                .await;
        assert!(!result, "timestamp exactly at boundary must be rejected");
    }

    #[test]
    fn config_rejects_zero_idle_timeout() {
        let config = LightningServerConfig {
            idle_timeout_secs: 0,
            ..Default::default()
        };
        let result = LightningServer::with_config("test".into(), "0.0.0.0".into(), 8443, config);
        assert!(result.is_err());
    }

    #[test]
    fn typed_handler_roundtrips_serde_struct() {
        #[derive(serde::Deserialize)]
        struct Req {
            x: i32,
            y: String,
        }
        #[derive(serde::Serialize)]
        struct Resp {
            sum: i32,
            echo: String,
        }

        let handler = typed_handler(|req: Req| -> std::result::Result<Resp, String> {
            Ok(Resp {
                sum: req.x + 1,
                echo: req.y,
            })
        });

        let mut data = HashMap::new();
        data.insert("x".to_string(), rmpv::Value::Integer(41.into()));
        data.insert("y".to_string(), rmpv::Value::String("hello".into()));

        let result = handler.handle("test", data).unwrap();
        assert_eq!(result.get("sum").unwrap(), &rmpv::Value::Integer(42.into()));
        assert_eq!(
            result.get("echo").unwrap(),
            &rmpv::Value::String("hello".into())
        );
    }

    #[tokio::test]
    async fn typed_async_handler_roundtrips_serde_struct() {
        #[derive(serde::Deserialize)]
        struct Req {
            value: i32,
        }
        #[derive(serde::Serialize)]
        struct Resp {
            doubled: i32,
        }

        let handler = typed_async_handler(|req: Req| async move {
            Ok::<_, String>(Resp {
                doubled: req.value * 2,
            })
        });

        let mut data = HashMap::new();
        data.insert("value".to_string(), rmpv::Value::Integer(21.into()));

        let result = handler.handle("test", data).await.unwrap();
        assert_eq!(
            result.get("doubled").unwrap(),
            &rmpv::Value::Integer(42.into())
        );
    }

    #[test]
    fn typed_handler_propagates_error() {
        let handler = typed_handler(|_req: HashMap<String, String>| -> std::result::Result<HashMap<String, String>, String> {
            Err("something went wrong".into())
        });

        let data = HashMap::new();
        let err = handler.handle("test", data).unwrap_err();
        assert!(err.to_string().contains("something went wrong"));
    }

    #[test]
    fn config_rejects_zero_max_connections() {
        let config = LightningServerConfig {
            max_connections: 0,
            ..Default::default()
        };
        let result = LightningServer::with_config("test".into(), "0.0.0.0".into(), 8443, config);
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_signature_age_exceeding_one_hour() {
        let config = LightningServerConfig {
            max_signature_age_secs: 3601,
            ..Default::default()
        };
        let result = LightningServer::with_config("test".into(), "0.0.0.0".into(), 8443, config);
        assert!(result.is_err());
    }

    #[test]
    fn config_accepts_signature_age_at_one_hour() {
        let config = LightningServerConfig {
            max_signature_age_secs: 3600,
            ..Default::default()
        };
        let result = LightningServer::with_config("test".into(), "0.0.0.0".into(), 8443, config);
        assert!(result.is_ok());
    }

    #[test]
    fn default_config_is_valid() {
        let result = LightningServer::new("test".into(), "0.0.0.0".into(), 8443);
        assert!(result.is_ok());
    }
}
