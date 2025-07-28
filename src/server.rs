use crate::types::{HandshakeRequest, HandshakeResponse, SynapsePacket, SynapseResponse};
use pyo3::prelude::*;
use quinn::{
    Connection, Endpoint, IdleTimeout, RecvStream, SendStream, ServerConfig, TransportConfig,
};
use rustls::{Certificate, PrivateKey, ServerConfig as RustlsServerConfig};
use serde_json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

use base64::{prelude::BASE64_STANDARD, Engine};
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use tracing::{debug, error, info, warn};

const MAX_SIGNATURE_AGE: u64 = 300;

#[derive(Debug, Clone)]
pub struct ValidatorConnection {
    #[allow(dead_code)]
    pub validator_hotkey: String,
    pub connection_id: String,
    #[allow(dead_code)]
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
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
        self.last_activity = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

pub struct LightningServer {
    miner_hotkey: String,
    miner_keypair_bytes: Option<[u8; 32]>,
    host: String,
    port: u16,
    connections: Arc<RwLock<HashMap<String, ValidatorConnection>>>,
    synapse_handlers: Arc<RwLock<HashMap<String, PyObject>>>,
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
            synapse_handlers: Arc::new(RwLock::new(HashMap::new())),
            endpoint: None,
        }
    }

    pub async fn register_synapse_handler(
        &self,
        synapse_type: String,
        handler: PyObject,
    ) -> PyResult<()> {
        let mut handlers = self.synapse_handlers.write().await;
        handlers.insert(synapse_type.clone(), handler);
        info!("📝 Registered synapse handler for: {}", synapse_type);
        Ok(())
    }

    fn create_self_signed_cert(
    ) -> Result<(Vec<Certificate>, PrivateKey), Box<dyn std::error::Error>> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let cert_der = cert.serialize_der()?;
        let priv_key = cert.serialize_private_key_der();

        Ok((vec![Certificate(cert_der)], PrivateKey(priv_key)))
    }

    pub async fn start(&mut self) -> PyResult<()> {
        info!(
            "🚀 Starting Lightning QUIC server on {}:{}",
            self.host, self.port
        );
        let (certs, key) = Self::create_self_signed_cert().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to create certificate: {}",
                e
            ))
        })?;

        let mut server_config = RustlsServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to configure TLS: {}",
                    e
                ))
            })?;

        server_config.alpn_protocols = vec![b"lightning-quic".to_vec()];
        let mut transport_config = TransportConfig::default();
        let idle_timeout = IdleTimeout::try_from(Duration::from_secs(150)).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to set idle timeout: {}",
                e
            ))
        })?;
        transport_config.max_idle_timeout(Some(idle_timeout));
        transport_config.keep_alive_interval(Some(Duration::from_secs(30)));

        let mut server_config = ServerConfig::with_crypto(Arc::new(server_config));
        server_config.transport_config(Arc::new(transport_config));
        let addr: SocketAddr = format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid address: {}", e))
            })?;

        let endpoint = Endpoint::server(server_config, addr).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to create QUIC endpoint: {}",
                e
            ))
        })?;

        info!("✅ QUIC endpoint created, listening on {}", addr);
        self.endpoint = Some(endpoint);

        Ok(())
    }

    pub async fn serve_forever(&mut self) -> PyResult<()> {
        if let Some(endpoint) = &self.endpoint {
            while let Some(conn) = endpoint.accept().await {
                let connections = self.connections.clone();
                let synapse_handlers = self.synapse_handlers.clone();
                let miner_hotkey = self.miner_hotkey.clone();
                let miner_keypair = self.miner_keypair_bytes.clone();

                tokio::spawn(async move {
                    match conn.await {
                        Ok(connection) => {
                            Self::handle_connection(
                                connection,
                                connections,
                                synapse_handlers,
                                miner_hotkey,
                                miner_keypair,
                            )
                            .await;
                        }
                        Err(e) => {
                            error!("❌ Connection failed: {}", e);
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
        synapse_handlers: Arc<RwLock<HashMap<String, PyObject>>>,
        miner_hotkey: String,
        miner_keypair: Option<[u8; 32]>,
    ) {
        let connection = Arc::new(connection);

        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    let conn_clone = connection.clone();
                    let connections_clone = connections.clone();
                    let handlers_clone = synapse_handlers.clone();
                    let miner_hotkey_clone = miner_hotkey.clone();
                    let miner_keypair_clone = miner_keypair.clone();

                    tokio::spawn(async move {
                        Self::handle_stream(
                            send,
                            recv,
                            conn_clone,
                            connections_clone,
                            handlers_clone,
                            miner_hotkey_clone,
                            miner_keypair_clone,
                        )
                        .await;
                    });
                }
                Err(e) => {
                    error!("❌ Stream error: {}", e);
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
        synapse_handlers: Arc<RwLock<HashMap<String, PyObject>>>,
        miner_hotkey: String,
        miner_keypair: Option<[u8; 32]>,
    ) {
        match recv.read_to_end(1024 * 1024).await {
            Ok(buffer) => {
                let message = String::from_utf8_lossy(&buffer);

                if let Ok(handshake_req) = serde_json::from_str::<HandshakeRequest>(&message) {
                    let response = Self::process_handshake(
                        handshake_req,
                        connection.clone(),
                        connections,
                        miner_hotkey,
                        miner_keypair,
                    )
                    .await;

                    if let Ok(response_json) = serde_json::to_string(&response) {
                        let _ = send.write_all(response_json.as_bytes()).await;
                        let _ = send.finish().await;
                    }
                    return;
                }

                if let Ok(synapse_packet) = serde_json::from_str::<SynapsePacket>(&message) {
                    let response = Self::process_synapse_packet(
                        synapse_packet,
                        connection.clone(),
                        connections,
                        synapse_handlers,
                    )
                    .await;

                    if let Ok(response_json) = serde_json::to_string(&response) {
                        let _ = send.write_all(response_json.as_bytes()).await;
                        let _ = send.finish().await;
                    }
                    return;
                }

                warn!("⚠️ Unknown message format received");
            }
            Err(e) => {
                error!("❌ Failed to read stream: {}", e);
            }
        }
    }

    async fn process_handshake(
        request: HandshakeRequest,
        connection: Arc<quinn::Connection>,
        connections: Arc<RwLock<HashMap<String, ValidatorConnection>>>,
        miner_hotkey: String,
        miner_keypair: Option<[u8; 32]>,
    ) -> HandshakeResponse {
        let is_valid = Self::verify_validator_signature(&request).await;

        if is_valid {
            let connection_id = format!(
                "conn_{}_{}",
                request.validator_hotkey,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
            );

            let mut connections_guard = connections.write().await;
            let mut validator_conn = ValidatorConnection::new(
                request.validator_hotkey.clone(),
                connection_id.clone(),
                connection.clone(),
            );
            validator_conn.verify();
            connections_guard.insert(request.validator_hotkey.clone(), validator_conn);

            info!(
                "✅ Handshake successful, established connection: {}",
                connection_id
            );

            HandshakeResponse {
                miner_hotkey: miner_hotkey.clone(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                signature: Self::sign_handshake_response(&request, &miner_hotkey, &miner_keypair)
                    .await,
                accepted: true,
                connection_id,
            }
        } else {
            error!("❌ Handshake failed: invalid signature");
            HandshakeResponse {
                miner_hotkey: miner_hotkey.clone(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                signature: String::new(),
                accepted: false,
                connection_id: String::new(),
            }
        }
    }

    async fn verify_validator_signature(request: &HandshakeRequest) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if current_time > request.timestamp
            && (current_time - request.timestamp) > MAX_SIGNATURE_AGE
        {
            error!(
                "❌ Signature timestamp too old: {} (current: {})",
                request.timestamp, current_time
            );
            return false;
        }

        if request.timestamp > current_time + 60 {
            error!(
                "❌ Signature timestamp too far in future: {} (current: {})",
                request.timestamp, current_time
            );
            return false;
        }

        let expected_message = format!(
            "handshake:{}:{}",
            request.validator_hotkey, request.timestamp
        );

        match sr25519::Public::from_ss58check(&request.validator_hotkey) {
            Ok(public_key) => match BASE64_STANDARD.decode(&request.signature) {
                Ok(signature_bytes) => {
                    if signature_bytes.len() != 64 {
                        error!("❌ Invalid signature length: {}", signature_bytes.len());
                        return false;
                    }

                    let mut signature_array = [0u8; 64];
                    signature_array.copy_from_slice(&signature_bytes);
                    let signature = sr25519::Signature::from_raw(signature_array);

                    let message_bytes = expected_message.as_bytes();

                    let verification_result =
                        sr25519::Pair::verify(&signature, message_bytes, &public_key);

                    if verification_result {
                        true
                    } else {
                        false
                    }
                }
                Err(e) => {
                    error!("❌ Failed to decode base64 signature: {}", e);
                    false
                }
            },
            Err(e) => {
                error!(
                    "❌ Invalid SS58 address {}: {}",
                    request.validator_hotkey, e
                );
                false
            }
        }
    }

    async fn sign_handshake_response(
        request: &HandshakeRequest,
        _miner_hotkey: &str,
        miner_keypair: &Option<[u8; 32]>,
    ) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let message = format!(
            "handshake_response:{}:{}",
            request.validator_hotkey, timestamp
        );

        match miner_keypair {
            Some(keypair_seed) => {
                let pair = sr25519::Pair::from_seed(keypair_seed);
                let signature = pair.sign(message.as_bytes());
                let signature_bytes = signature.0;
                BASE64_STANDARD.encode(signature_bytes)
            }
            None => {
                warn!("⚠️ No miner keypair configured, using dummy signature");
                let dummy_bytes = &message.as_bytes()[..8];
                BASE64_STANDARD.encode(dummy_bytes)
            }
        }
    }

    async fn process_synapse_packet(
        packet: SynapsePacket,
        connection: Arc<quinn::Connection>,
        connections: Arc<RwLock<HashMap<String, ValidatorConnection>>>,
        synapse_handlers: Arc<RwLock<HashMap<String, PyObject>>>,
    ) -> SynapseResponse {
        debug!("📦 Processing {} synapse packet", packet.synapse_type);

        let validator_hotkey = {
            let connections_guard = connections.read().await;
            connections_guard
                .iter()
                .find(|(_, validator_conn)| {
                    validator_conn.connection.remote_address() == connection.remote_address()
                })
                .map(|(hotkey, _)| hotkey.clone())
                .unwrap_or_else(|| {
                    warn!(
                        "⚠️ No validator found for connection from {}",
                        connection.remote_address()
                    );
                    "unknown_validator".to_string()
                })
        };

        {
            let mut connections_guard = connections.write().await;
            if let Some(connection) = connections_guard.get_mut(&validator_hotkey) {
                if !connection.verified {
                    error!(
                        "❌ Connection not verified for validator: {}",
                        validator_hotkey
                    );
                    return SynapseResponse {
                        success: false,
                        data: HashMap::new(),
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        error: Some("Connection not verified".to_string()),
                    };
                }
                connection.update_activity();
                debug!(
                    "✅ Connection verified and activity updated for validator: {}",
                    validator_hotkey
                );
            } else {
                warn!(
                    "⚠️ No connection found for validator {}, allowing request to proceed",
                    validator_hotkey
                );
            }
        }

        let handlers = synapse_handlers.read().await;
        if let Some(handler) = handlers.get(&packet.synapse_type) {
            match pyo3::Python::with_gil(|py| -> PyResult<HashMap<String, serde_json::Value>> {
                let py_dict = pyo3::types::PyDict::new(py);

                for (key, value) in &packet.data {
                    let py_value = match value {
                        serde_json::Value::String(s) => s.to_object(py),
                        serde_json::Value::Number(n) => {
                            if let Some(i) = n.as_i64() {
                                i.to_object(py)
                            } else if let Some(f) = n.as_f64() {
                                f.to_object(py)
                            } else {
                                n.to_string().to_object(py)
                            }
                        }
                        serde_json::Value::Bool(b) => b.to_object(py),
                        serde_json::Value::Array(arr) => {
                            let py_list = pyo3::types::PyList::empty(py);
                            for item in arr {
                                let item_str = serde_json::to_string(item).unwrap_or_default();
                                py_list.append(item_str)?;
                            }
                            py_list.to_object(py)
                        }
                        serde_json::Value::Object(_) => serde_json::to_string(value)
                            .unwrap_or_default()
                            .to_object(py),
                        serde_json::Value::Null => py.None(),
                    };
                    py_dict.set_item(key, py_value)?;
                }

                let result = handler.call1(py, (py_dict,))?;

                let result_dict: &pyo3::types::PyDict = result.extract(py)?;
                let mut response_data = HashMap::new();

                for (key, value) in result_dict.iter() {
                    let key_str: String = key.extract()?;
                    let value_json = if let Ok(s) = value.extract::<String>() {
                        serde_json::Value::String(s)
                    } else if let Ok(b) = value.extract::<bool>() {
                        serde_json::Value::Bool(b)
                    } else if let Ok(i) = value.extract::<i64>() {
                        serde_json::Value::Number(serde_json::Number::from(i))
                    } else if let Ok(f) = value.extract::<f64>() {
                        serde_json::Number::from_f64(f)
                            .map(serde_json::Value::Number)
                            .unwrap_or(serde_json::Value::Null)
                    } else {
                        let s: String = value.str()?.extract()?;
                        serde_json::Value::String(s)
                    };
                    response_data.insert(key_str, value_json);
                }

                Ok(response_data)
            }) {
                Ok(response_data) => SynapseResponse {
                    success: true,
                    data: response_data,
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    error: None,
                },
                Err(e) => {
                    error!("❌ Python handler error for {}: {}", packet.synapse_type, e);
                    error!("❌ Python error details: {:?}", e);

                    let mut error_data = HashMap::new();
                    error_data.insert(
                        "error".to_string(),
                        serde_json::Value::String(format!("Python handler error: {}", e)),
                    );

                    SynapseResponse {
                        success: false,
                        data: error_data,
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        error: Some(format!("Python handler error: {}", e)),
                    }
                }
            }
        } else {
            error!(
                "❌ No handler registered for synapse type: {}",
                packet.synapse_type
            );
            SynapseResponse {
                success: false,
                data: HashMap::new(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                error: Some(format!(
                    "No handler for synapse type: {}",
                    packet.synapse_type
                )),
            }
        }
    }

    pub async fn get_connection_stats(&self) -> PyResult<HashMap<String, String>> {
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

    pub async fn cleanup_stale_connections(&self, max_idle_seconds: u64) -> PyResult<()> {
        let mut connections = self.connections.write().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut to_remove = Vec::new();
        for (validator, connection) in connections.iter() {
            if now - connection.last_activity > max_idle_seconds {
                to_remove.push(validator.clone());
            }
        }

        for validator in to_remove {
            if let Some(connection) = connections.remove(&validator) {
                connection.connection.close(0u32.into(), b"cleanup");
                info!(
                    "🧹 Cleaned up stale connection from validator: {}",
                    validator
                );
            }
        }

        Ok(())
    }

    pub async fn stop(&self) -> PyResult<()> {
        let mut connections = self.connections.write().await;
        for (_, connection) in connections.drain() {
            connection.connection.close(0u32.into(), b"server_shutdown");
        }

        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0u32.into(), b"server_shutdown");
        }

        info!("🔌 Lightning QUIC server stopped, all connections closed");
        Ok(())
    }
}
