use crate::error::{LightningError, Result};
use crate::types::{HandshakeRequest, HandshakeResponse, SynapsePacket, SynapseResponse};
use crate::util::{unix_timestamp_secs, MAX_RESPONSE_SIZE};
use base64::{prelude::BASE64_STANDARD, Engine};
use quinn::{
    Connection, Endpoint, IdleTimeout, RecvStream, SendStream, ServerConfig, TransportConfig,
};
use rustls::{Certificate, PrivateKey, ServerConfig as RustlsServerConfig};
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

fn synapse_finder() -> &'static memchr::memmem::Finder<'static> {
    static FINDER: OnceLock<memchr::memmem::Finder<'static>> = OnceLock::new();
    FINDER.get_or_init(|| memchr::memmem::Finder::new(b"\"synapse_type\""))
}

const MAX_SIGNATURE_AGE: u64 = 300;

pub trait SynapseHandler: Send + Sync {
    fn handle(
        &self,
        synapse_type: &str,
        data: HashMap<String, serde_json::Value>,
    ) -> Result<HashMap<String, serde_json::Value>>;
}

#[derive(Debug, Clone)]
pub struct ValidatorConnection {
    pub validator_hotkey: String,
    pub connection_id: String,
    pub established_at: u64,
    pub last_activity: u64,
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
            last_activity: now,
            verified: false,
            connection: conn,
        }
    }

    pub fn verify(&mut self) {
        self.verified = true;
        self.update_activity();
    }

    pub fn update_activity(&mut self) {
        self.last_activity = unix_timestamp_secs();
    }
}

pub struct LightningServer {
    miner_hotkey: String,
    miner_keypair_bytes: Option<[u8; 32]>,
    host: String,
    port: u16,
    connections: Arc<RwLock<HashMap<String, ValidatorConnection>>>,
    addr_to_hotkey: Arc<RwLock<HashMap<SocketAddr, String>>>,
    synapse_handlers: Arc<RwLock<HashMap<String, Arc<dyn SynapseHandler>>>>,
    used_nonces: Arc<RwLock<HashMap<String, u64>>>,
    endpoint: Option<Endpoint>,
}

impl LightningServer {
    pub fn new(miner_hotkey: String, host: String, port: u16) -> Self {
        Self {
            miner_hotkey,
            miner_keypair_bytes: None,
            host,
            port,
            connections: Arc::new(RwLock::new(HashMap::new())),
            addr_to_hotkey: Arc::new(RwLock::new(HashMap::new())),
            synapse_handlers: Arc::new(RwLock::new(HashMap::new())),
            used_nonces: Arc::new(RwLock::new(HashMap::new())),
            endpoint: None,
        }
    }

    pub fn set_miner_keypair(&mut self, keypair_bytes: [u8; 32]) {
        self.miner_keypair_bytes = Some(keypair_bytes);
    }

    pub async fn register_synapse_handler(
        &self,
        synapse_type: String,
        handler: Arc<dyn SynapseHandler>,
    ) -> Result<()> {
        let mut handlers = self.synapse_handlers.write().await;
        handlers.insert(synapse_type.clone(), handler);
        info!("Registered synapse handler for: {}", synapse_type);
        Ok(())
    }

    fn create_self_signed_cert(
    ) -> std::result::Result<(Vec<Certificate>, PrivateKey), Box<dyn std::error::Error>> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let cert_der = cert.serialize_der()?;
        let priv_key = cert.serialize_private_key_der();

        Ok((vec![Certificate(cert_der)], PrivateKey(priv_key)))
    }

    pub async fn start(&mut self) -> Result<()> {
        info!("Starting Lightning QUIC server on {}:{}", self.host, self.port);
        let (certs, key) = Self::create_self_signed_cert().map_err(|e| {
            LightningError::Config(format!("Failed to create certificate: {}", e))
        })?;

        let mut server_config = RustlsServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| LightningError::Config(format!("Failed to configure TLS: {}", e)))?;

        server_config.alpn_protocols = vec![b"lightning-quic".to_vec()];
        let mut transport_config = TransportConfig::default();
        let idle_timeout = IdleTimeout::try_from(Duration::from_secs(150)).map_err(|e| {
            LightningError::Config(format!("Failed to set idle timeout: {}", e))
        })?;
        transport_config.max_idle_timeout(Some(idle_timeout));
        transport_config.keep_alive_interval(Some(Duration::from_secs(30)));

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
        if let Some(endpoint) = &self.endpoint {
            let nonces_for_cleanup = self.used_nonces.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    let mut nonces = nonces_for_cleanup.write().await;
                    let cutoff = unix_timestamp_secs().saturating_sub(MAX_SIGNATURE_AGE);
                    nonces.retain(|_, ts| *ts > cutoff);
                }
            });

            while let Some(conn) = endpoint.accept().await {
                let connections = self.connections.clone();
                let addr_to_hotkey = self.addr_to_hotkey.clone();
                let synapse_handlers = self.synapse_handlers.clone();
                let used_nonces = self.used_nonces.clone();
                let miner_hotkey = self.miner_hotkey.clone();
                let miner_keypair = self.miner_keypair_bytes;

                tokio::spawn(async move {
                    match conn.await {
                        Ok(connection) => {
                            Self::handle_connection(
                                connection,
                                connections,
                                addr_to_hotkey,
                                synapse_handlers,
                                used_nonces,
                                miner_hotkey,
                                miner_keypair,
                            )
                            .await;
                        }
                        Err(e) => {
                            error!("Connection failed: {}", e);
                        }
                    }
                });
            }
        }
        Ok(())
    }

    async fn handle_connection(
        connection: Connection,
        connections: Arc<RwLock<HashMap<String, ValidatorConnection>>>,
        addr_to_hotkey: Arc<RwLock<HashMap<SocketAddr, String>>>,
        synapse_handlers: Arc<RwLock<HashMap<String, Arc<dyn SynapseHandler>>>>,
        used_nonces: Arc<RwLock<HashMap<String, u64>>>,
        miner_hotkey: String,
        miner_keypair: Option<[u8; 32]>,
    ) {
        let connection = Arc::new(connection);

        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    let conn_clone = connection.clone();
                    let connections_clone = connections.clone();
                    let addr_to_hotkey_clone = addr_to_hotkey.clone();
                    let handlers_clone = synapse_handlers.clone();
                    let nonces_clone = used_nonces.clone();
                    let miner_hotkey_clone = miner_hotkey.clone();
                    let miner_keypair_clone = miner_keypair;

                    tokio::spawn(async move {
                        Self::handle_stream(
                            send,
                            recv,
                            conn_clone,
                            connections_clone,
                            addr_to_hotkey_clone,
                            handlers_clone,
                            nonces_clone,
                            miner_hotkey_clone,
                            miner_keypair_clone,
                        )
                        .await;
                    });
                }
                Err(e) => {
                    error!("Stream error: {}", e);
                    break;
                }
            }
        }
    }

    async fn handle_stream(
        mut send: SendStream,
        mut recv: RecvStream,
        connection: Arc<quinn::Connection>,
        connections: Arc<RwLock<HashMap<String, ValidatorConnection>>>,
        addr_to_hotkey: Arc<RwLock<HashMap<SocketAddr, String>>>,
        synapse_handlers: Arc<RwLock<HashMap<String, Arc<dyn SynapseHandler>>>>,
        used_nonces: Arc<RwLock<HashMap<String, u64>>>,
        miner_hotkey: String,
        miner_keypair: Option<[u8; 32]>,
    ) {
        match recv.read_to_end(MAX_RESPONSE_SIZE).await {
            Ok(buffer) => {
                if synapse_finder().find(&buffer).is_some() {
                    match serde_json::from_slice::<SynapsePacket>(&buffer) {
                        Ok(synapse_packet) => {
                            let response = Self::process_synapse_packet(
                                synapse_packet,
                                connection.clone(),
                                connections,
                                addr_to_hotkey,
                                synapse_handlers,
                            )
                            .await;

                            match serde_json::to_vec(&response) {
                                Ok(response_bytes) => {
                                    let _ = send.write_all(&response_bytes).await;
                                    let _ = send.finish().await;
                                }
                                Err(e) => {
                                    error!("Failed to serialize SynapseResponse: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse synapse packet: {}", e);
                            let err_response = SynapseResponse {
                                success: false,
                                data: HashMap::new(),
                                timestamp: unix_timestamp_secs(),
                                error: Some(e.to_string()),
                            };
                            match serde_json::to_vec(&err_response) {
                                Ok(bytes) => {
                                    let _ = send.write_all(&bytes).await;
                                    let _ = send.finish().await;
                                }
                                Err(e) => {
                                    error!("Failed to serialize SynapseResponse error: {}", e);
                                }
                            }
                        }
                    }
                } else {
                    match serde_json::from_slice::<HandshakeRequest>(&buffer) {
                        Ok(handshake_req) => {
                            let response = Self::process_handshake(
                                handshake_req,
                                connection.clone(),
                                connections,
                                addr_to_hotkey,
                                used_nonces,
                                miner_hotkey,
                                miner_keypair,
                            )
                            .await;

                            match serde_json::to_vec(&response) {
                                Ok(response_bytes) => {
                                    let _ = send.write_all(&response_bytes).await;
                                    let _ = send.finish().await;
                                }
                                Err(e) => {
                                    error!("Failed to serialize HandshakeResponse: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Unknown message format received: {}", e);
                            let err_response = HandshakeResponse {
                                miner_hotkey,
                                timestamp: unix_timestamp_secs(),
                                signature: String::new(),
                                accepted: false,
                                connection_id: String::new(),
                            };
                            match serde_json::to_vec(&err_response) {
                                Ok(bytes) => {
                                    let _ = send.write_all(&bytes).await;
                                    let _ = send.finish().await;
                                }
                                Err(e) => {
                                    error!("Failed to serialize HandshakeResponse error: {}", e);
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to read stream: {}", e);
            }
        }
    }

    async fn process_handshake(
        request: HandshakeRequest,
        connection: Arc<quinn::Connection>,
        connections: Arc<RwLock<HashMap<String, ValidatorConnection>>>,
        addr_to_hotkey: Arc<RwLock<HashMap<SocketAddr, String>>>,
        used_nonces: Arc<RwLock<HashMap<String, u64>>>,
        miner_hotkey: String,
        miner_keypair: Option<[u8; 32]>,
    ) -> HandshakeResponse {
        let is_valid =
            Self::verify_validator_signature(&request, used_nonces).await;

        if is_valid {
            let now = unix_timestamp_secs();
            let connection_id = format!(
                "conn_{}_{}",
                request.validator_hotkey,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_millis()
            );

            let remote_addr = connection.remote_address();
            let mut connections_guard = connections.write().await;
            let mut addr_index = addr_to_hotkey.write().await;
            let mut validator_conn = ValidatorConnection::new(
                request.validator_hotkey.clone(),
                connection_id.clone(),
                connection.clone(),
            );
            validator_conn.verify();
            if let Some(prev_conn) = connections_guard.insert(request.validator_hotkey.clone(), validator_conn) {
                let prev_addr = prev_conn.connection.remote_address();
                if prev_addr != remote_addr {
                    addr_index.remove(&prev_addr);
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
                miner_hotkey: miner_hotkey.clone(),
                timestamp: now,
                signature: Self::sign_handshake_response(&request, &miner_keypair, now),
                accepted: true,
                connection_id,
            }
        } else {
            error!("Handshake failed: invalid signature");
            HandshakeResponse {
                miner_hotkey: miner_hotkey.clone(),
                timestamp: unix_timestamp_secs(),
                signature: String::new(),
                accepted: false,
                connection_id: String::new(),
            }
        }
    }

    async fn verify_validator_signature(
        request: &HandshakeRequest,
        used_nonces: Arc<RwLock<HashMap<String, u64>>>,
    ) -> bool {
        let current_time = unix_timestamp_secs();

        if current_time > request.timestamp
            && (current_time - request.timestamp) > MAX_SIGNATURE_AGE
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

        let expected_message = format!(
            "handshake:{}:{}:{}",
            request.validator_hotkey, request.timestamp, request.nonce
        );

        let public_key = match sr25519::Public::from_ss58check(&request.validator_hotkey) {
            Ok(pk) => pk,
            Err(e) => {
                error!(
                    "Invalid SS58 address {}: {}",
                    request.validator_hotkey, e
                );
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

        let valid = tokio::task::spawn_blocking(move || {
            sr25519::Pair::verify(&signature, expected_message.as_bytes(), &public_key)
        })
        .await
        .unwrap_or(false);

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
        miner_keypair: &Option<[u8; 32]>,
        timestamp: u64,
    ) -> String {
        let message = format!(
            "handshake_response:{}:{}",
            request.validator_hotkey, timestamp
        );

        match miner_keypair {
            Some(keypair_seed) => {
                let pair = sr25519::Pair::from_seed(keypair_seed);
                let signature = pair.sign(message.as_bytes());
                BASE64_STANDARD.encode(signature.0)
            }
            None => {
                warn!("No miner keypair configured, using empty signature");
                String::new()
            }
        }
    }

    async fn process_synapse_packet(
        packet: SynapsePacket,
        connection: Arc<quinn::Connection>,
        connections: Arc<RwLock<HashMap<String, ValidatorConnection>>>,
        addr_to_hotkey: Arc<RwLock<HashMap<SocketAddr, String>>>,
        synapse_handlers: Arc<RwLock<HashMap<String, Arc<dyn SynapseHandler>>>>,
    ) -> SynapseResponse {
        debug!("Processing {} synapse packet", packet.synapse_type);

        let validator_hotkey = {
            let addr_index = addr_to_hotkey.read().await;
            match addr_index.get(&connection.remote_address()).cloned() {
                Some(hotkey) => hotkey,
                None => {
                    error!(
                        "Unknown or unauthenticated connection from {}",
                        connection.remote_address()
                    );
                    return SynapseResponse {
                        success: false,
                        data: HashMap::new(),
                        timestamp: unix_timestamp_secs(),
                        error: Some("Unknown or unauthenticated validator".to_string()),
                    };
                }
            }
        };

        {
            let mut connections_guard = connections.write().await;
            if let Some(connection) = connections_guard.get_mut(&validator_hotkey) {
                if !connection.verified {
                    error!(
                        "Connection not verified for validator: {}",
                        validator_hotkey
                    );
                    return SynapseResponse {
                        success: false,
                        data: HashMap::new(),
                        timestamp: unix_timestamp_secs(),
                        error: Some("Connection not verified".to_string()),
                    };
                }
                connection.update_activity();
                debug!(
                    "Connection verified and activity updated for validator: {}",
                    validator_hotkey
                );
            } else {
                error!(
                    "No connection found for validator {}",
                    validator_hotkey
                );
                return SynapseResponse {
                    success: false,
                    data: HashMap::new(),
                    timestamp: unix_timestamp_secs(),
                    error: Some("Unknown or unauthenticated validator".to_string()),
                };
            }
        }

        let handlers = synapse_handlers.read().await;
        if let Some(handler) = handlers.get(&packet.synapse_type) {
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

    pub async fn get_connection_stats(&self) -> Result<HashMap<String, String>> {
        let connections = self.connections.read().await;
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
        let mut connections = self.connections.write().await;
        let now = unix_timestamp_secs();

        let mut to_remove = Vec::new();
        for (validator, connection) in connections.iter() {
            if now.saturating_sub(connection.last_activity) > max_idle_seconds {
                to_remove.push((validator.clone(), connection.connection.remote_address()));
            }
        }

        let mut addr_index = self.addr_to_hotkey.write().await;
        for (validator, remote_addr) in &to_remove {
            if let Some(connection) = connections.remove(validator) {
                connection.connection.close(0u32.into(), b"cleanup");
                info!(
                    "Cleaned up stale connection from validator: {}",
                    validator
                );
            }
            addr_index.remove(remote_addr);
        }

        Ok(())
    }

    pub async fn cleanup_expired_nonces(&self) {
        let mut nonces = self.used_nonces.write().await;
        let cutoff = unix_timestamp_secs().saturating_sub(MAX_SIGNATURE_AGE);
        nonces.retain(|_, ts| *ts > cutoff);
    }

    pub async fn stop(&self) -> Result<()> {
        let mut connections = self.connections.write().await;
        let mut addr_index = self.addr_to_hotkey.write().await;
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
