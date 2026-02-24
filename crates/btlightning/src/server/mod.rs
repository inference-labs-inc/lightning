mod config;
mod dispatch;
mod handshake;
mod response;

pub use config::LightningServerConfig;

use crate::error::{LightningError, Result};
#[cfg(feature = "btwallet")]
use crate::signing::BtWalletSigner;
use crate::signing::{Signer, Sr25519Signer};
use crate::types::{hashmap_to_rmpv_map, serialize_to_rmpv_map};
use crate::util::unix_timestamp_secs;
use indexmap::IndexMap;
use quinn::{Endpoint, IdleTimeout, ServerConfig, TransportConfig, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig as RustlsServerConfig;
use sp_core::blake2_256;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{error, info, instrument, warn};

pub trait ValidatorPermitResolver: Send + Sync {
    fn resolve_permitted_validators(&self) -> Result<HashSet<String>>;
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
    verified: bool,
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

    pub fn is_verified(&self) -> bool {
        self.verified
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
    used_nonces: Arc<RwLock<IndexMap<String, u64>>>,
    handshake_rate: Arc<RwLock<HashMap<IpAddr, Vec<u64>>>>,
    permit_resolver: Option<Arc<dyn ValidatorPermitResolver>>,
    permitted_validators: Arc<RwLock<HashSet<String>>>,
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
    permit_refresh_handle: Arc<tokio::sync::Mutex<Option<JoinHandle<()>>>>,
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
        config.validate()?;
        Ok(Self {
            host,
            port,
            ctx: ServerContext {
                connections: Arc::new(RwLock::new(HashMap::new())),
                addr_to_hotkey: Arc::new(RwLock::new(HashMap::new())),
                synapse_handlers: Arc::new(RwLock::new(HashMap::new())),
                async_handlers: Arc::new(RwLock::new(HashMap::new())),
                streaming_handlers: Arc::new(RwLock::new(HashMap::new())),
                used_nonces: Arc::new(RwLock::new(IndexMap::new())),
                handshake_rate: Arc::new(RwLock::new(HashMap::new())),
                permit_resolver: None,
                permitted_validators: Arc::new(RwLock::new(HashSet::new())),
                miner_hotkey,
                miner_signer: None,
                cert_fingerprint: Arc::new(RwLock::new(None)),
                config,
            },
            endpoint: None,
            cleanup_handle: Arc::new(tokio::sync::Mutex::new(None)),
            permit_refresh_handle: Arc::new(tokio::sync::Mutex::new(None)),
        })
    }

    pub fn set_miner_keypair(&mut self, keypair_bytes: [u8; 32]) {
        self.ctx.miner_signer = Some(Arc::new(Sr25519Signer::from_seed(keypair_bytes)));
    }

    pub fn set_miner_signer(&mut self, signer: Box<dyn Signer>) {
        self.ctx.miner_signer = Some(Arc::from(signer));
    }

    pub fn set_validator_permit_resolver(&mut self, resolver: Box<dyn ValidatorPermitResolver>) {
        self.ctx.permit_resolver = Some(Arc::from(resolver));
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

    #[instrument(skip(self, handler), fields(%synapse_type))]
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

    #[instrument(skip(self, handler), fields(%synapse_type))]
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

    #[instrument(skip(self, handler), fields(%synapse_type))]
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
    fn create_self_signed_cert() -> std::result::Result<
        (
            Vec<CertificateDer<'static>>,
            PrivateKeyDer<'static>,
            [u8; 32],
        ),
        Box<dyn std::error::Error>,
    > {
        let key_pair = rcgen::KeyPair::generate()?;
        let params = rcgen::CertificateParams::new(vec!["localhost".into()])?;
        let cert = params.self_signed(&key_pair)?;
        let cert_der = cert.der().to_vec();
        let fingerprint = blake2_256(&cert_der);

        Ok((
            vec![CertificateDer::from(cert_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
            fingerprint,
        ))
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .as_ref()
            .ok_or_else(|| {
                LightningError::Config("server not started: call start() first".to_string())
            })?
            .local_addr()
            .map_err(|e| LightningError::Config(format!("failed to get local address: {}", e)))
    }

    #[instrument(skip(self), fields(host = %self.host, port = self.port))]
    pub async fn start(&mut self) -> Result<()> {
        info!(
            "Starting Lightning QUIC server on {}:{}",
            self.host, self.port
        );
        let (certs, key, fingerprint) = Self::create_self_signed_cert()
            .map_err(|e| LightningError::Config(format!("Failed to create certificate: {}", e)))?;

        *self.ctx.cert_fingerprint.write().await = Some(fingerprint);

        let mut server_config = RustlsServerConfig::builder()
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
        transport_config.max_concurrent_bidi_streams(VarInt::from_u32(
            self.ctx.config.max_concurrent_bidi_streams,
        ));
        transport_config.max_concurrent_uni_streams(VarInt::from_u32(0));

        let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_config)
            .map_err(|e| {
                LightningError::Config(format!("Failed to create QUIC crypto config: {}", e))
            })?;
        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
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

    #[instrument(skip(self))]
    pub async fn serve_forever(&self) -> Result<()> {
        let endpoint = self.endpoint.as_ref().ok_or_else(|| {
            LightningError::Config("server not started: call start() first".to_string())
        })?;
        if self.ctx.config.require_validator_permit {
            if self.ctx.permit_resolver.is_none() {
                return Err(LightningError::Config(
                    "require_validator_permit is enabled but no ValidatorPermitResolver is configured".to_string(),
                ));
            }
        } else {
            info!("Validator permit checking is disabled -- any hotkey with a valid signature can connect");
        }

        {
            let mut guard = self.cleanup_handle.lock().await;
            if let Some(old) = guard.take() {
                old.abort();
            }
        }

        let nonces_for_cleanup = self.ctx.used_nonces.clone();
        let rate_for_cleanup = self.ctx.handshake_rate.clone();
        let cleanup_interval_secs = self.ctx.config.nonce_cleanup_interval_secs;
        let max_sig_age = self.ctx.config.max_signature_age_secs;
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(cleanup_interval_secs));
            interval.tick().await;
            loop {
                interval.tick().await;
                let now = unix_timestamp_secs();
                let cutoff = now.saturating_sub(max_sig_age);
                let mut nonces = nonces_for_cleanup.write().await;
                nonces.retain(|_, ts| *ts >= cutoff);
                drop(nonces);
                let rate_cutoff = now.saturating_sub(60);
                let mut rates = rate_for_cleanup.write().await;
                rates.retain(|_, attempts| {
                    attempts.retain(|ts| *ts >= rate_cutoff);
                    !attempts.is_empty()
                });
            }
        });
        *self.cleanup_handle.lock().await = Some(handle);

        {
            let mut guard = self.permit_refresh_handle.lock().await;
            if let Some(old) = guard.take() {
                old.abort();
            }
        }

        if let Some(resolver) = &self.ctx.permit_resolver {
            let r = resolver.clone();
            match tokio::task::spawn_blocking(move || r.resolve_permitted_validators()).await {
                Ok(Ok(set)) => {
                    info!(
                        "Initial validator permit resolution: {} permitted validators",
                        set.len()
                    );
                    *self.ctx.permitted_validators.write().await = set;
                }
                Ok(Err(e)) => {
                    error!("Initial validator permit resolution failed: {}", e);
                }
                Err(e) => {
                    error!("Initial validator permit resolution task panicked: {}", e);
                }
            }

            let resolver = resolver.clone();
            let permitted = self.ctx.permitted_validators.clone();
            let refresh_secs = self.ctx.config.validator_permit_refresh_secs;
            let permit_handle = tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(refresh_secs));
                interval.tick().await;
                loop {
                    interval.tick().await;
                    let r = resolver.clone();
                    match tokio::task::spawn_blocking(move || r.resolve_permitted_validators())
                        .await
                    {
                        Ok(Ok(set)) => {
                            info!(
                                "Refreshed validator permit cache: {} permitted validators",
                                set.len()
                            );
                            *permitted.write().await = set;
                        }
                        Ok(Err(e)) => {
                            error!("Validator permit resolution failed: {}", e);
                        }
                        Err(e) => {
                            error!("Validator permit resolution task panicked: {}", e);
                        }
                    }
                }
            });
            *self.permit_refresh_handle.lock().await = Some(permit_handle);
        }

        while let Some(conn) = endpoint.accept().await {
            let ctx = self.ctx.clone();

            {
                let connections = ctx.connections.read().await;
                if connections.len() >= ctx.config.max_connections {
                    let addr_index = ctx.addr_to_hotkey.read().await;
                    if !addr_index.contains_key(&conn.remote_address()) {
                        warn!(
                            "Connection limit reached ({}/{}), refusing incoming connection from {}",
                            connections.len(),
                            ctx.config.max_connections,
                            conn.remote_address()
                        );
                        conn.refuse();
                        continue;
                    }
                }
            }

            tokio::spawn(async move {
                match conn.accept() {
                    Ok(connecting) => match connecting.await {
                        Ok(connection) => {
                            dispatch::handle_connection(connection, ctx).await;
                        }
                        Err(e) => {
                            error!("Connection failed: {}", e);
                        }
                    },
                    Err(e) => {
                        error!("Connection accept failed: {}", e);
                    }
                }
            });
        }
        Ok(())
    }

    #[instrument(skip(self))]
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
                .filter(|c| c.is_verified())
                .count()
                .to_string(),
        );

        for (validator, connection) in connections.iter() {
            if connection.is_verified() {
                stats.insert(
                    format!("connection_{}", validator),
                    connection.connection_id.clone(),
                );
            }
        }

        Ok(stats)
    }

    #[instrument(skip(self))]
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

    pub async fn get_active_nonce_count(&self) -> usize {
        self.ctx.used_nonces.read().await.len()
    }

    pub async fn get_permitted_validator_count(&self) -> usize {
        self.ctx.permitted_validators.read().await.len()
    }

    #[instrument(skip(self))]
    pub async fn cleanup_expired_nonces(&self) {
        let mut nonces = self.ctx.used_nonces.write().await;
        let cutoff = unix_timestamp_secs().saturating_sub(self.ctx.config.max_signature_age_secs);
        nonces.retain(|_, ts| *ts >= cutoff);
    }

    #[instrument(skip(self))]
    pub async fn stop(&self) -> Result<()> {
        if let Some(handle) = self.cleanup_handle.lock().await.take() {
            handle.abort();
        }
        if let Some(handle) = self.permit_refresh_handle.lock().await.take() {
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

impl Drop for LightningServer {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.cleanup_handle.try_lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        if let Ok(mut guard) = self.permit_refresh_handle.try_lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0u32.into(), b"dropped");
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
    use crate::types::HandshakeRequest;
    use base64::{prelude::BASE64_STANDARD, Engine};
    use sp_core::{crypto::Ss58Codec, Pair};

    fn test_server_context(config: LightningServerConfig) -> ServerContext {
        ServerContext {
            connections: Arc::new(RwLock::new(HashMap::new())),
            addr_to_hotkey: Arc::new(RwLock::new(HashMap::new())),
            synapse_handlers: Arc::new(RwLock::new(HashMap::new())),
            async_handlers: Arc::new(RwLock::new(HashMap::new())),
            streaming_handlers: Arc::new(RwLock::new(HashMap::new())),
            used_nonces: Arc::new(RwLock::new(IndexMap::new())),
            handshake_rate: Arc::new(RwLock::new(HashMap::new())),
            permit_resolver: None,
            permitted_validators: Arc::new(RwLock::new(HashSet::new())),
            miner_hotkey: String::new(),
            miner_signer: None,
            cert_fingerprint: Arc::new(RwLock::new(None)),
            config,
        }
    }

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
            nonce: "00000000000000000000000000000000".to_string(),
            signature: String::new(),
        };
        let nonces = Arc::new(RwLock::new(IndexMap::new()));
        let result = handshake::verify_validator_signature(
            &request,
            nonces,
            &[0u8; 32],
            max_signature_age,
            100_000,
        )
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

    fn make_signed_request(nonce: &str, fp: &[u8; 32]) -> HandshakeRequest {
        use crate::types::handshake_request_message;
        let pair = sp_core::sr25519::Pair::from_seed(&[1u8; 32]);
        let hotkey = pair.public().to_ss58check();
        let timestamp = unix_timestamp_secs();
        let fp_b64 = BASE64_STANDARD.encode(fp);
        let message = handshake_request_message(&hotkey, timestamp, nonce, &fp_b64);
        let signature = pair.sign(message.as_bytes());
        HandshakeRequest {
            validator_hotkey: hotkey,
            timestamp,
            nonce: nonce.to_string(),
            signature: BASE64_STANDARD.encode(signature.0),
        }
    }

    #[tokio::test]
    async fn verify_rejects_nonce_replay() {
        let nonces = Arc::new(RwLock::new(IndexMap::new()));
        let fp = [0u8; 32];
        let request = make_signed_request("00000000000000000000000000000001", &fp);

        let result =
            handshake::verify_validator_signature(&request, nonces.clone(), &fp, 300, 100_000)
                .await;
        assert!(result, "first use of nonce must succeed");
        assert!(
            nonces
                .read()
                .await
                .contains_key("00000000000000000000000000000001"),
            "nonce must be consumed after successful verification"
        );

        let result =
            handshake::verify_validator_signature(&request, nonces.clone(), &fp, 300, 100_000)
                .await;
        assert!(!result, "replayed nonce must be rejected");
    }

    #[test]
    fn config_rejects_zero_handshake_timeout() {
        let config = LightningServerConfig {
            handshake_timeout_secs: 0,
            ..Default::default()
        };
        let result = LightningServer::with_config("test".into(), "0.0.0.0".into(), 8443, config);
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_handshake_timeout_ge_idle_timeout() {
        let config = LightningServerConfig {
            handshake_timeout_secs: 150,
            idle_timeout_secs: 150,
            ..Default::default()
        };
        let result = LightningServer::with_config("test".into(), "0.0.0.0".into(), 8443, config);
        assert!(result.is_err());

        let config = LightningServerConfig {
            handshake_timeout_secs: 200,
            idle_timeout_secs: 150,
            ..Default::default()
        };
        let result = LightningServer::with_config("test".into(), "0.0.0.0".into(), 8443, config);
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_zero_max_handshake_attempts() {
        let config = LightningServerConfig {
            max_handshake_attempts_per_minute: 0,
            ..Default::default()
        };
        let result = LightningServer::with_config("test".into(), "0.0.0.0".into(), 8443, config);
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_zero_max_concurrent_bidi_streams() {
        let config = LightningServerConfig {
            max_concurrent_bidi_streams: 0,
            ..Default::default()
        };
        let result = LightningServer::with_config("test".into(), "0.0.0.0".into(), 8443, config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rate_limiter_allows_within_limit() {
        let ctx = test_server_context(LightningServerConfig {
            max_handshake_attempts_per_minute: 3,
            ..Default::default()
        });
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        assert!(handshake::check_handshake_rate(&ctx, ip).await);
        assert!(handshake::check_handshake_rate(&ctx, ip).await);
        assert!(handshake::check_handshake_rate(&ctx, ip).await);
        assert!(
            !handshake::check_handshake_rate(&ctx, ip).await,
            "fourth attempt must be rejected"
        );
    }

    #[tokio::test]
    async fn rate_limiter_isolates_ips() {
        let ctx = test_server_context(LightningServerConfig {
            max_handshake_attempts_per_minute: 1,
            ..Default::default()
        });
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        assert!(handshake::check_handshake_rate(&ctx, ip1).await);
        assert!(
            !handshake::check_handshake_rate(&ctx, ip1).await,
            "ip1 must be rate limited"
        );
        assert!(
            handshake::check_handshake_rate(&ctx, ip2).await,
            "ip2 must not be affected by ip1 rate limit"
        );
    }

    #[tokio::test]
    async fn rate_limiter_evicts_oldest_ip_at_cap() {
        let ctx = test_server_context(LightningServerConfig {
            max_handshake_attempts_per_minute: 10,
            max_tracked_rate_ips: 2,
            ..Default::default()
        });

        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let ip3: IpAddr = "10.0.0.3".parse().unwrap();

        assert!(handshake::check_handshake_rate(&ctx, ip1).await);
        assert!(handshake::check_handshake_rate(&ctx, ip2).await);
        assert_eq!(ctx.handshake_rate.read().await.len(), 2);

        assert!(handshake::check_handshake_rate(&ctx, ip3).await);
        let rates = ctx.handshake_rate.read().await;
        assert!(
            rates.len() <= 2,
            "map must not exceed max_tracked_rate_ips, got {}",
            rates.len()
        );
        assert!(
            rates.contains_key(&ip3),
            "newly inserted IP must be present"
        );
    }

    #[test]
    fn config_rejects_zero_max_tracked_rate_ips() {
        let config = LightningServerConfig {
            max_tracked_rate_ips: 0,
            ..Default::default()
        };
        let result = LightningServer::with_config("test".into(), "0.0.0.0".into(), 8443, config);
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_zero_handler_timeout() {
        let config = LightningServerConfig {
            handler_timeout_secs: 0,
            ..Default::default()
        };
        let result = LightningServer::with_config("test".into(), "0.0.0.0".into(), 8443, config);
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_handler_timeout_exceeding_idle() {
        let config = LightningServerConfig {
            handler_timeout_secs: 200,
            idle_timeout_secs: 150,
            ..Default::default()
        };
        let result = LightningServer::with_config("test".into(), "0.0.0.0".into(), 8443, config);
        assert!(result.is_err());

        let equal = LightningServerConfig {
            handler_timeout_secs: 150,
            idle_timeout_secs: 150,
            ..Default::default()
        };
        let result = LightningServer::with_config("test".into(), "0.0.0.0".into(), 8443, equal);
        assert!(result.is_err());
    }

    #[test]
    fn config_defaults_validator_permit_disabled() {
        let config = LightningServerConfig::default();
        assert!(!config.require_validator_permit);
        assert_eq!(config.validator_permit_refresh_secs, 1800);
    }

    #[test]
    fn config_rejects_zero_validator_permit_refresh() {
        let config = LightningServerConfig {
            validator_permit_refresh_secs: 0,
            ..Default::default()
        };
        let result = LightningServer::with_config("test".into(), "0.0.0.0".into(), 8443, config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn nonce_hard_cap_evicts_oldest() {
        let nonces = Arc::new(RwLock::new(IndexMap::new()));
        for i in 0..5u64 {
            nonces
                .write()
                .await
                .insert(format!("nonce-{}", i), 1000 + i);
        }

        let fp = [0u8; 32];
        let request = make_signed_request("00000000000000000000000000000002", &fp);

        let _ = handshake::verify_validator_signature(&request, nonces.clone(), &fp, 300, 3).await;

        let nonces_guard = nonces.read().await;
        assert!(
            nonces_guard.len() <= 3,
            "hard cap must enforce max_nonce_entries"
        );
        assert!(
            !nonces_guard.contains_key("nonce-0"),
            "oldest nonce should be evicted first"
        );
        assert!(
            !nonces_guard.contains_key("nonce-1"),
            "second-oldest nonce should be evicted"
        );
        assert!(
            !nonces_guard.contains_key("nonce-2"),
            "third-oldest nonce should be evicted"
        );
    }

    #[tokio::test]
    async fn verify_rejects_invalid_nonce_format() {
        let nonces = Arc::new(RwLock::new(IndexMap::new()));
        let request = HandshakeRequest {
            validator_hotkey: String::new(),
            timestamp: unix_timestamp_secs(),
            nonce: "not-a-hex-nonce".to_string(),
            signature: String::new(),
        };
        let result =
            handshake::verify_validator_signature(&request, nonces, &[0u8; 32], 300, 100_000).await;
        assert!(!result, "non-hex nonce must be rejected");
    }

    #[tokio::test]
    async fn verify_rejects_short_nonce() {
        let nonces = Arc::new(RwLock::new(IndexMap::new()));
        let request = HandshakeRequest {
            validator_hotkey: String::new(),
            timestamp: unix_timestamp_secs(),
            nonce: "abcdef".to_string(),
            signature: String::new(),
        };
        let result =
            handshake::verify_validator_signature(&request, nonces, &[0u8; 32], 300, 100_000).await;
        assert!(!result, "short nonce must be rejected");
    }

    #[tokio::test]
    async fn verify_rejects_future_timestamp() {
        let nonces = Arc::new(RwLock::new(IndexMap::new()));
        let request = HandshakeRequest {
            validator_hotkey: String::new(),
            timestamp: unix_timestamp_secs() + 120,
            nonce: "00000000000000000000000000000003".to_string(),
            signature: String::new(),
        };
        let result =
            handshake::verify_validator_signature(&request, nonces, &[0u8; 32], 300, 100_000).await;
        assert!(!result, "timestamp > now + 60 must be rejected");
    }

    #[tokio::test]
    async fn verify_rejects_invalid_ss58() {
        let nonces = Arc::new(RwLock::new(IndexMap::new()));
        let request = HandshakeRequest {
            validator_hotkey: "not_valid_ss58".to_string(),
            timestamp: unix_timestamp_secs(),
            nonce: "00000000000000000000000000000004".to_string(),
            signature: BASE64_STANDARD.encode([0u8; 64]),
        };
        let result =
            handshake::verify_validator_signature(&request, nonces, &[0u8; 32], 300, 100_000).await;
        assert!(!result, "invalid SS58 address must be rejected");
    }

    #[tokio::test]
    async fn verify_rejects_invalid_base64_signature() {
        let pair = sp_core::sr25519::Pair::from_seed(&[1u8; 32]);
        let hotkey = pair.public().to_ss58check();
        let nonces = Arc::new(RwLock::new(IndexMap::new()));
        let request = HandshakeRequest {
            validator_hotkey: hotkey,
            timestamp: unix_timestamp_secs(),
            nonce: "00000000000000000000000000000005".to_string(),
            signature: "not-valid-base64!!!".to_string(),
        };
        let result =
            handshake::verify_validator_signature(&request, nonces, &[0u8; 32], 300, 100_000).await;
        assert!(!result, "invalid base64 signature must be rejected");
    }

    #[tokio::test]
    async fn verify_rejects_wrong_signature_length() {
        let pair = sp_core::sr25519::Pair::from_seed(&[1u8; 32]);
        let hotkey = pair.public().to_ss58check();
        let nonces = Arc::new(RwLock::new(IndexMap::new()));
        let request = HandshakeRequest {
            validator_hotkey: hotkey,
            timestamp: unix_timestamp_secs(),
            nonce: "00000000000000000000000000000006".to_string(),
            signature: BASE64_STANDARD.encode([0u8; 32]),
        };
        let result =
            handshake::verify_validator_signature(&request, nonces, &[0u8; 32], 300, 100_000).await;
        assert!(!result, "32-byte signature must be rejected (need 64)");
    }

    #[tokio::test]
    async fn verify_rejects_cryptographically_invalid_signature() {
        let pair = sp_core::sr25519::Pair::from_seed(&[1u8; 32]);
        let hotkey = pair.public().to_ss58check();
        let nonces = Arc::new(RwLock::new(IndexMap::new()));
        let request = HandshakeRequest {
            validator_hotkey: hotkey,
            timestamp: unix_timestamp_secs(),
            nonce: "00000000000000000000000000000007".to_string(),
            signature: BASE64_STANDARD.encode([0u8; 64]),
        };
        let result =
            handshake::verify_validator_signature(&request, nonces, &[0u8; 32], 300, 100_000).await;
        assert!(!result, "wrong signature bytes must be rejected");
    }

    #[tokio::test]
    async fn verify_accepts_valid_signature() {
        use crate::types::handshake_request_message;

        let pair = sp_core::sr25519::Pair::from_seed(&[1u8; 32]);
        let hotkey = pair.public().to_ss58check();
        let timestamp = unix_timestamp_secs();
        let nonce = "00000000000000000000000000000008";
        let fp = [0u8; 32];
        let fp_b64 = BASE64_STANDARD.encode(fp);
        let message = handshake_request_message(&hotkey, timestamp, nonce, &fp_b64);
        let signature = pair.sign(message.as_bytes());

        let nonces = Arc::new(RwLock::new(IndexMap::new()));
        let request = HandshakeRequest {
            validator_hotkey: hotkey,
            timestamp,
            nonce: nonce.to_string(),
            signature: BASE64_STANDARD.encode(signature.0),
        };
        let result =
            handshake::verify_validator_signature(&request, nonces, &fp, 300, 100_000).await;
        assert!(result, "correctly signed request must be accepted");
    }

    #[tokio::test]
    async fn sign_handshake_response_fails_without_signer() {
        let request = HandshakeRequest {
            validator_hotkey: "test".to_string(),
            timestamp: 0,
            nonce: "n".to_string(),
            signature: String::new(),
        };
        let result =
            handshake::sign_handshake_response(&request, "miner", None, 0, &[0u8; 32]).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("no miner signer configured"));
    }

    #[tokio::test]
    async fn sign_handshake_response_succeeds_with_signer() {
        let signer: Arc<dyn Signer> = Arc::new(crate::signing::Sr25519Signer::from_seed([1u8; 32]));
        let request = HandshakeRequest {
            validator_hotkey: "test".to_string(),
            timestamp: unix_timestamp_secs(),
            nonce: "n".to_string(),
            signature: String::new(),
        };
        let result =
            handshake::sign_handshake_response(&request, "miner", Some(signer), 0, &[0u8; 32])
                .await;
        let b64 = result.unwrap();
        let decoded = BASE64_STANDARD.decode(&b64).unwrap();
        assert_eq!(decoded.len(), 64);
    }
}
