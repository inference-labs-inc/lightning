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

/// Resolves the set of validator hotkeys allowed to connect.
///
/// Called periodically by the server (interval controlled by
/// [`LightningServerConfig::validator_permit_refresh_secs`]). Return the full set each
/// time; the server replaces the cached set atomically.
pub trait ValidatorPermitResolver: Send + Sync {
    /// Returns the current set of permitted validator SS58 hotkeys.
    fn resolve_permitted_validators(&self) -> Result<HashSet<String>>;
}

/// Synchronous synapse request handler.
///
/// Runs on a blocking thread. Use [`AsyncSynapseHandler`] for async work or
/// [`StreamingSynapseHandler`] for chunked responses.
pub trait SynapseHandler: Send + Sync {
    /// Processes the request and returns the response payload map.
    fn handle(
        &self,
        synapse_type: &str,
        data: HashMap<String, rmpv::Value>,
    ) -> Result<HashMap<String, rmpv::Value>>;
}

/// Async synapse request handler.
///
/// Preferred over [`SynapseHandler`] when the handler performs I/O or other async work.
#[async_trait::async_trait]
pub trait AsyncSynapseHandler: Send + Sync {
    /// Processes the request asynchronously and returns the response payload map.
    async fn handle(
        &self,
        synapse_type: &str,
        data: HashMap<String, rmpv::Value>,
    ) -> Result<HashMap<String, rmpv::Value>>;
}

/// Streaming synapse handler that sends response chunks incrementally.
///
/// Send raw byte chunks through the `sender` channel. The server frames each chunk
/// as a `StreamChunk` and sends a `StreamEnd` when the handler returns.
#[async_trait::async_trait]
pub trait StreamingSynapseHandler: Send + Sync {
    /// Processes the request, writing response chunks to `sender`.
    async fn handle(
        &self,
        synapse_type: &str,
        data: HashMap<String, rmpv::Value>,
        sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> Result<()>;
}

/// Server-side state for an authenticated validator QUIC connection.
#[derive(Debug)]
pub struct ValidatorConnection {
    /// SS58 hotkey of the connected validator.
    pub validator_hotkey: String,
    /// Opaque connection identifier returned in the handshake response.
    pub connection_id: String,
    /// UNIX timestamp when the connection was established.
    pub established_at: u64,
    /// UNIX timestamp of last synapse activity (atomically updated).
    pub last_activity: AtomicU64,
    verified: bool,
    /// Underlying QUIC connection handle.
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

    /// Marks this connection as handshake-verified and updates the activity timestamp.
    pub fn verify(&mut self) {
        self.verified = true;
        self.update_activity();
    }

    /// Returns whether the handshake has been verified for this connection.
    pub fn is_verified(&self) -> bool {
        self.verified
    }

    /// Bumps the `last_activity` timestamp to now.
    pub fn update_activity(&self) {
        self.last_activity
            .store(unix_timestamp_secs(), Ordering::Relaxed);
    }
}

pub(super) fn evict_stale_nonces(
    nonces: &mut IndexMap<String, u64>,
    now: u64,
    max_age: u64,
    hard_cap: Option<usize>,
) {
    let cutoff = now.saturating_sub(max_age);
    nonces.retain(|_, ts| *ts > cutoff);
    if let Some(cap) = hard_cap {
        while nonces.len() > cap {
            nonces.shift_remove_index(0);
        }
    }
}

pub(super) fn remove_hotkey_from_maps(
    connections: &mut HashMap<String, ValidatorConnection>,
    addr_to_hotkey: &mut HashMap<SocketAddr, String>,
    hotkey: &str,
) -> Option<ValidatorConnection> {
    if let Some(conn) = connections.remove(hotkey) {
        addr_to_hotkey.remove(&conn.connection.remote_address());
        Some(conn)
    } else {
        None
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

/// QUIC server that accepts validator connections and dispatches synapse requests to handlers.
///
/// Lifecycle: [`new`](Self::new) / [`with_config`](Self::with_config) -> register handlers ->
/// [`start`](Self::start) -> [`serve_forever`](Self::serve_forever).
pub struct LightningServer {
    host: String,
    port: u16,
    ctx: ServerContext,
    endpoint: Option<Endpoint>,
    cleanup_handle: Arc<tokio::sync::Mutex<Option<JoinHandle<()>>>>,
    permit_refresh_handle: Arc<tokio::sync::Mutex<Option<JoinHandle<()>>>>,
}

macro_rules! register_handler {
    ($method:ident, $field:ident, $trait:ident, $label:expr) => {
        #[instrument(skip(self, handler), fields(%synapse_type))]
        pub async fn $method(&self, synapse_type: String, handler: Arc<dyn $trait>) -> Result<()> {
            let mut handlers = self.ctx.$field.write().await;
            handlers.insert(synapse_type.clone(), handler);
            info!(
                concat!("Registered ", $label, " handler for: {}"),
                synapse_type
            );
            Ok(())
        }
    };
}

impl LightningServer {
    /// Creates a server with default configuration.
    pub fn new(miner_hotkey: String, host: String, port: u16) -> Result<Self> {
        Self::with_config(miner_hotkey, host, port, LightningServerConfig::default())
    }

    /// Creates a server with the given configuration, validating constraints.
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

    /// Sets the miner signer from a raw 32-byte sr25519 seed.
    pub fn set_miner_keypair(&mut self, keypair_bytes: [u8; 32]) {
        self.ctx.miner_signer = Some(Arc::new(Sr25519Signer::from_seed(keypair_bytes)));
    }

    /// Sets a custom [`Signer`] for handshake response signing.
    pub fn set_miner_signer(&mut self, signer: Box<dyn Signer>) {
        self.ctx.miner_signer = Some(Arc::from(signer));
    }

    /// Sets the [`ValidatorPermitResolver`] used to gate incoming connections.
    pub fn set_validator_permit_resolver(&mut self, resolver: Box<dyn ValidatorPermitResolver>) {
        self.ctx.permit_resolver = Some(Arc::from(resolver));
    }

    /// Loads the miner signer from a Bittensor wallet on disk. Requires the `btwallet` feature.
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

    register_handler!(
        register_synapse_handler,
        synapse_handlers,
        SynapseHandler,
        "synapse"
    );
    register_handler!(
        register_async_synapse_handler,
        async_handlers,
        AsyncSynapseHandler,
        "async synapse"
    );
    register_handler!(
        register_streaming_handler,
        streaming_handlers,
        StreamingSynapseHandler,
        "streaming"
    );

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

    /// Returns the local socket address the server is bound to. Requires [`start`](Self::start).
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .as_ref()
            .ok_or_else(|| {
                LightningError::Config("server not started: call start() first".to_string())
            })?
            .local_addr()
            .map_err(|e| LightningError::Config(format!("failed to get local address: {}", e)))
    }

    /// Creates the QUIC endpoint and TLS certificate. Does not accept connections yet;
    /// call [`serve_forever`](Self::serve_forever) after this.
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

    /// Enters the accept loop, handling incoming QUIC connections until the endpoint is closed.
    /// Spawns nonce cleanup and validator permit refresh background tasks.
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
                let mut nonces = nonces_for_cleanup.write().await;
                evict_stale_nonces(&mut nonces, now, max_sig_age, None);
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

    /// Returns a map of connection statistics (total, verified, per-validator).
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

    /// Closes connections idle for longer than `max_idle_seconds`.
    #[instrument(skip(self))]
    pub async fn cleanup_stale_connections(&self, max_idle_seconds: u64) -> Result<()> {
        let mut connections = self.ctx.connections.write().await;
        let now = unix_timestamp_secs();

        let stale: Vec<String> = connections
            .iter()
            .filter(|(_, conn)| {
                now.saturating_sub(conn.last_activity.load(Ordering::Relaxed)) > max_idle_seconds
            })
            .map(|(hotkey, _)| hotkey.clone())
            .collect();

        let mut addr_index = self.ctx.addr_to_hotkey.write().await;
        let removed: Vec<(String, ValidatorConnection)> = stale
            .iter()
            .filter_map(|hotkey| {
                remove_hotkey_from_maps(&mut connections, &mut addr_index, hotkey)
                    .map(|conn| (hotkey.clone(), conn))
            })
            .collect();
        drop(addr_index);
        drop(connections);

        for (hotkey, conn) in removed {
            conn.connection.close(0u32.into(), b"cleanup");
            info!("Cleaned up stale connection from validator: {}", hotkey);
        }

        Ok(())
    }

    /// Returns the number of nonces currently stored in the replay-protection set.
    pub async fn get_active_nonce_count(&self) -> usize {
        self.ctx.used_nonces.read().await.len()
    }

    /// Returns the number of validators in the current permit set.
    pub async fn get_permitted_validator_count(&self) -> usize {
        self.ctx.permitted_validators.read().await.len()
    }

    /// Manually evicts expired nonces from the replay-protection set.
    #[instrument(skip(self))]
    pub async fn cleanup_expired_nonces(&self) {
        let now = unix_timestamp_secs();
        let mut nonces = self.ctx.used_nonces.write().await;
        evict_stale_nonces(
            &mut nonces,
            now,
            self.ctx.config.max_signature_age_secs,
            None,
        );
    }

    /// Gracefully shuts down the server: aborts background tasks, closes all connections,
    /// and closes the QUIC endpoint.
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

/// Wraps a typed synchronous closure as a [`SynapseHandler`].
///
/// The closure receives a deserialized `Req` and returns `Result<Resp, E>`.
/// Serialization to/from the MessagePack data map is handled automatically.
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

/// Wraps a typed async closure as an [`AsyncSynapseHandler`].
///
/// The closure receives a deserialized `Req` and returns `Future<Output = Result<Resp, E>>`.
/// Serialization to/from the MessagePack data map is handled automatically.
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

    #[test]
    fn evict_stale_nonces_trims_to_hard_cap() {
        let now = unix_timestamp_secs();
        let mut nonces = IndexMap::new();
        for i in 0..5 {
            nonces.insert(format!("nonce_{}", i), now);
        }
        evict_stale_nonces(&mut nonces, now, 300, Some(3));
        assert_eq!(nonces.len(), 3);
        assert!(!nonces.contains_key("nonce_0"));
        assert!(!nonces.contains_key("nonce_1"));
        assert!(nonces.contains_key("nonce_2"));
        assert!(nonces.contains_key("nonce_3"));
        assert!(nonces.contains_key("nonce_4"));
    }

    #[test]
    fn evict_stale_nonces_removes_expired_before_cap() {
        let now = 1000;
        let mut nonces = IndexMap::new();
        nonces.insert("old".to_string(), 600);
        nonces.insert("recent".to_string(), 800);
        evict_stale_nonces(&mut nonces, now, 300, Some(10));
        assert_eq!(nonces.len(), 1);
        assert!(nonces.contains_key("recent"));
    }

    #[test]
    fn evict_stale_nonces_boundary_removes_exact_cutoff() {
        let now = 1000;
        let mut nonces = IndexMap::new();
        nonces.insert("at_cutoff".to_string(), 700);
        nonces.insert("after_cutoff".to_string(), 701);
        evict_stale_nonces(&mut nonces, now, 300, None);
        assert_eq!(nonces.len(), 1);
        assert!(nonces.contains_key("after_cutoff"));
    }

    #[tokio::test]
    async fn remove_hotkey_from_maps_cleans_both() {
        let (server_endpoint, server_addr) = {
            let (certs, key, _) = LightningServer::create_self_signed_cert().unwrap();
            let server_crypto = RustlsServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();
            let quic_crypto =
                quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap();
            let server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
            let ep = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
            let addr = ep.local_addr().unwrap();
            (ep, addr)
        };

        let client_endpoint = {
            use rustls::client::danger::{
                HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
            };
            use rustls::pki_types::{CertificateDer as RustlsCert, ServerName, UnixTime};
            use rustls::ClientConfig as RustlsClientConfig;
            use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

            #[derive(Debug)]
            struct InsecureVerifier;
            impl ServerCertVerifier for InsecureVerifier {
                fn verify_server_cert(
                    &self,
                    _: &RustlsCert<'_>,
                    _: &[RustlsCert<'_>],
                    _: &ServerName<'_>,
                    _: &[u8],
                    _: UnixTime,
                ) -> std::result::Result<ServerCertVerified, TlsError> {
                    Ok(ServerCertVerified::assertion())
                }
                fn verify_tls12_signature(
                    &self,
                    _: &[u8],
                    _: &RustlsCert<'_>,
                    _: &DigitallySignedStruct,
                ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
                    Err(TlsError::PeerIncompatible(
                        rustls::PeerIncompatible::Tls12NotOffered,
                    ))
                }
                fn verify_tls13_signature(
                    &self,
                    _: &[u8],
                    _: &RustlsCert<'_>,
                    _: &DigitallySignedStruct,
                ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
                    Ok(HandshakeSignatureValid::assertion())
                }
                fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                    vec![
                        SignatureScheme::ECDSA_NISTP256_SHA256,
                        SignatureScheme::ECDSA_NISTP384_SHA384,
                        SignatureScheme::ED25519,
                    ]
                }
            }

            let tls = RustlsClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
                .with_no_client_auth();
            let client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
            let mut ep = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
            ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));
            ep
        };

        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.unwrap();
            Arc::new(incoming.await.unwrap())
        });

        let client_conn = client_endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let server_conn = server_task.await.unwrap();

        let remote_addr = server_conn.remote_address();
        let hotkey = "test_validator".to_string();

        let mut connections = HashMap::new();
        let mut addr_to_hotkey = HashMap::new();
        let vc = ValidatorConnection::new(hotkey.clone(), "conn_1".into(), server_conn);
        addr_to_hotkey.insert(remote_addr, hotkey.clone());
        connections.insert(hotkey.clone(), vc);

        let removed = remove_hotkey_from_maps(&mut connections, &mut addr_to_hotkey, &hotkey);
        assert!(removed.is_some());
        assert!(connections.is_empty());
        assert!(!addr_to_hotkey.contains_key(&remote_addr));

        client_conn.close(0u32.into(), b"done");
    }

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
