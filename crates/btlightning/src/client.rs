use crate::connection_pool::ConnectionPool;
use crate::error::{LightningError, Result};
use crate::signing::Signer;
use crate::types::{
    HandshakeRequest, HandshakeResponse, QuicAxonInfo, QuicRequest, QuicResponse, SynapsePacket,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use quinn::{ClientConfig, Connection, Endpoint, IdleTimeout, TransportConfig};
use rustls::ClientConfig as RustlsClientConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{error, info};

pub const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn unix_timestamp_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
}

pub struct LightningClient {
    wallet_hotkey: String,
    signer: Option<Box<dyn Signer>>,
    connection_pool: Arc<RwLock<ConnectionPool>>,
    active_miners: Arc<RwLock<HashMap<String, QuicAxonInfo>>>,
    established_connections: Arc<RwLock<HashMap<String, Connection>>>,
    endpoint: Option<Endpoint>,
}

impl LightningClient {
    pub fn new(wallet_hotkey: String) -> Self {
        Self {
            wallet_hotkey,
            signer: None,
            connection_pool: Arc::new(RwLock::new(ConnectionPool::new())),
            active_miners: Arc::new(RwLock::new(HashMap::new())),
            established_connections: Arc::new(RwLock::new(HashMap::new())),
            endpoint: None,
        }
    }

    pub fn set_signer(&mut self, signer: Box<dyn Signer>) {
        self.signer = Some(signer);
        info!("Signer configured");
    }

    pub async fn initialize_connections(&mut self, miners: Vec<QuicAxonInfo>) -> Result<()> {
        self.create_endpoint().await?;

        let mut active_miners = self.active_miners.write().await;
        let mut pool = self.connection_pool.write().await;

        for miner in miners {
            let miner_key = format!("{}:{}", miner.ip, miner.port);

            match self.establish_connection_with_handshake(&miner).await {
                Ok(connection) => {
                    let connection_id =
                        format!("{}:{}:{}", miner.ip, miner.port, unix_timestamp_millis());

                    pool.add_connection(&miner_key, connection_id.clone())
                        .await;
                    active_miners.insert(miner_key.clone(), miner);

                    let mut connections = self.established_connections.write().await;
                    connections.insert(miner_key.clone(), connection);

                    info!(
                        "Established persistent QUIC connection to miner: {}",
                        miner_key
                    );
                }
                Err(e) => {
                    error!("Failed to connect to miner {}: {}", miner_key, e);
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

        tls_config.alpn_protocols = vec![b"lightning-quic".to_vec()];

        let mut transport_config = TransportConfig::default();

        let idle_timeout = IdleTimeout::try_from(Duration::from_secs(150))
            .map_err(|e| LightningError::Config(format!("Failed to set idle timeout: {}", e)))?;
        transport_config.max_idle_timeout(Some(idle_timeout));
        transport_config.keep_alive_interval(Some(Duration::from_secs(30)));

        let mut client_config = ClientConfig::new(Arc::new(tls_config));
        client_config.transport_config(Arc::new(transport_config));

        let bind_addr: SocketAddr = "0.0.0.0:0".parse().map_err(|e| {
            LightningError::Config(format!("Failed to parse bind address: {}", e))
        })?;
        let mut endpoint = Endpoint::client(bind_addr).map_err(|e| {
            LightningError::Connection(format!("Failed to create QUIC endpoint: {}", e))
        })?;
        endpoint.set_default_client_config(client_config);
        self.endpoint = Some(endpoint);

        info!("QUIC client endpoint created");
        Ok(())
    }

    async fn establish_connection_with_handshake(
        &self,
        miner: &QuicAxonInfo,
    ) -> Result<Connection> {
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or_else(|| LightningError::Connection("QUIC endpoint not initialized".into()))?;

        let addr: SocketAddr = format!("{}:{}", miner.ip, miner.port)
            .parse()
            .map_err(|e| LightningError::Connection(format!("Invalid address: {}", e)))?;

        let connection = endpoint
            .connect(addr, &miner.ip)
            .map_err(|e| LightningError::Connection(format!("Connection failed: {}", e)))?
            .await
            .map_err(|e| {
                LightningError::Connection(format!("Connection handshake failed: {}", e))
            })?;

        let nonce = generate_nonce();
        let handshake_request = HandshakeRequest {
            validator_hotkey: self.wallet_hotkey.clone(),
            timestamp: unix_timestamp_secs(),
            nonce: nonce.clone(),
            signature: self.sign_handshake_message(&nonce)?,
        };

        let response = self.send_handshake(&connection, handshake_request).await?;
        if response.accepted {
            info!("Handshake successful with miner {}", miner.hotkey);
            Ok(connection)
        } else {
            Err(LightningError::Handshake(
                "Handshake rejected by miner".into(),
            ))
        }
    }

    async fn send_handshake(
        &self,
        connection: &Connection,
        request: HandshakeRequest,
    ) -> Result<HandshakeResponse> {
        let (mut send, mut recv) = connection.open_bi().await.map_err(|e| {
            LightningError::Connection(format!("Failed to open bidirectional stream: {}", e))
        })?;

        let handshake_data = serde_json::to_value(&request).map_err(|e| {
            LightningError::Serialization(format!("Failed to serialize handshake data: {}", e))
        })?;

        let data = handshake_data
            .as_object()
            .ok_or_else(|| {
                LightningError::Serialization("Handshake data is not a JSON object".into())
            })?
            .clone()
            .into_iter()
            .collect();

        let synapse_packet = SynapsePacket {
            synapse_type: "Handshake".to_string(),
            data,
            timestamp: unix_timestamp_secs(),
        };

        let packet_json = serde_json::to_string(&synapse_packet).map_err(|e| {
            LightningError::Serialization(format!("Failed to serialize synapse packet: {}", e))
        })?;

        send.write_all(packet_json.as_bytes()).await.map_err(|e| {
            LightningError::Transport(format!("Failed to send handshake packet: {}", e))
        })?;
        send.finish().await.map_err(|e| {
            LightningError::Transport(format!("Failed to finish sending handshake: {}", e))
        })?;

        let buffer = recv
            .read_to_end(MAX_RESPONSE_SIZE)
            .await
            .map_err(|e| {
                LightningError::Transport(format!("Failed to read handshake response: {}", e))
            })?;

        let response_str = String::from_utf8(buffer).map_err(|e| {
            LightningError::Serialization(format!("Invalid UTF-8 in response: {}", e))
        })?;

        let response: HandshakeResponse = serde_json::from_str(&response_str).map_err(|e| {
            LightningError::Serialization(format!("Failed to parse handshake response: {}", e))
        })?;

        Ok(response)
    }

    fn sign_handshake_message(&self, nonce: &str) -> Result<String> {
        let timestamp = unix_timestamp_secs();
        let message = format!("handshake:{}:{}:{}", self.wallet_hotkey, timestamp, nonce);

        match &self.signer {
            Some(signer) => {
                let signature_bytes = signer.sign(message.as_bytes())?;
                Ok(BASE64_STANDARD.encode(&signature_bytes))
            }
            None => Err(LightningError::Signing("No signer configured".into())),
        }
    }

    pub async fn query_axon(
        &self,
        axon_info: QuicAxonInfo,
        request: QuicRequest,
    ) -> Result<QuicResponse> {
        let miner_key = format!("{}:{}", axon_info.ip, axon_info.port);

        let connections = self.established_connections.read().await;
        if let Some(connection) = connections.get(&miner_key) {
            if connection.close_reason().is_some() {
                return Err(LightningError::Connection(format!(
                    "Connection to miner {} is closed",
                    miner_key
                )));
            }
            self.send_synapse_packet(connection, request).await
        } else {
            Err(LightningError::Connection(format!(
                "No persistent QUIC connection to miner: {}",
                miner_key
            )))
        }
    }

    async fn send_synapse_packet(
        &self,
        connection: &Connection,
        request: QuicRequest,
    ) -> Result<QuicResponse> {
        let (mut send, mut recv) = connection.open_bi().await.map_err(|e| {
            LightningError::Connection(format!("Failed to open stream: {}", e))
        })?;

        let synapse_packet = SynapsePacket {
            synapse_type: request.synapse_type.clone(),
            data: request.data.clone(),
            timestamp: unix_timestamp_secs(),
        };

        let packet_json = serde_json::to_string(&synapse_packet).map_err(|e| {
            LightningError::Serialization(format!("Failed to serialize synapse packet: {}", e))
        })?;

        send.write_all(packet_json.as_bytes()).await.map_err(|e| {
            LightningError::Transport(format!("Failed to send synapse packet: {}", e))
        })?;
        send.finish().await.map_err(|e| {
            LightningError::Transport(format!("Failed to finish sending: {}", e))
        })?;

        let buffer = recv.read_to_end(MAX_RESPONSE_SIZE).await.map_err(|e| {
            LightningError::Transport(format!("Failed to read response: {}", e))
        })?;

        let response_str = String::from_utf8(buffer).map_err(|e| {
            LightningError::Serialization(format!("Invalid UTF-8 in response: {}", e))
        })?;

        let synapse_response: crate::types::SynapseResponse =
            serde_json::from_str(&response_str).map_err(|e| {
                LightningError::Serialization(format!(
                    "Failed to parse synapse response: {}",
                    e
                ))
            })?;

        Ok(QuicResponse {
            success: synapse_response.success,
            data: synapse_response.data,
            latency_ms: 0.0,
        })
    }

    pub async fn update_miner_registry(&mut self, miners: Vec<QuicAxonInfo>) -> Result<()> {
        let current_miners: HashMap<String, QuicAxonInfo> = miners
            .iter()
            .map(|m| (format!("{}:{}", m.ip, m.port), m.clone()))
            .collect();

        let mut active_miners = self.active_miners.write().await;
        let mut pool = self.connection_pool.write().await;
        let mut connections = self.established_connections.write().await;

        let active_keys: Vec<String> = active_miners.keys().cloned().collect();
        for key in active_keys {
            if !current_miners.contains_key(&key) {
                info!("Miner deregistered, closing QUIC connection: {}", key);
                if let Some(connection) = connections.remove(&key) {
                    connection.close(0u32.into(), b"miner_deregistered");
                }
                pool.remove_connection(&key).await;
                active_miners.remove(&key);
            }
        }

        for (key, miner) in current_miners {
            if !active_miners.contains_key(&key) {
                info!("New miner detected, establishing QUIC connection: {}", key);
                match self.establish_connection_with_handshake(&miner).await {
                    Ok(connection) => {
                        let connection_id =
                            format!("{}:{}:{}", miner.ip, miner.port, unix_timestamp_millis());

                        pool.add_connection(&key, connection_id).await;
                        active_miners.insert(key.clone(), miner);
                        connections.insert(key, connection);
                    }
                    Err(e) => {
                        error!("Failed to connect to new miner {}: {}", key, e);
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
            pool.connection_count().await.to_string(),
        );
        stats.insert("active_miners".to_string(), active_miners.len().to_string());
        stats.insert(
            "quic_connections".to_string(),
            connections.len().to_string(),
        );

        for (key, _) in active_miners.iter() {
            if let Some(connection_id) = pool.get_connection(key).await {
                stats.insert(format!("connection_{}", key), connection_id);
            }
        }

        Ok(stats)
    }

    pub async fn close_all_connections(&self) -> Result<()> {
        let mut pool = self.connection_pool.write().await;
        let mut active_miners = self.active_miners.write().await;
        let mut connections = self.established_connections.write().await;

        for (_, connection) in connections.drain() {
            connection.close(0u32.into(), b"client_shutdown");
        }

        pool.close_all().await;
        active_miners.clear();

        info!("All Lightning QUIC connections closed");
        Ok(())
    }
}

fn generate_nonce() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    unix_timestamp_millis().hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    format!("{:016x}", hasher.finish())
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
