use crate::error::{LightningError, Result};
use crate::signing::Signer;
use crate::types::{
    handshake_request_message, handshake_response_message, read_frame, write_frame_and_finish,
    HandshakeRequest, HandshakeResponse, MessageType, QuicAxonInfo, QuicRequest, QuicResponse,
    StreamChunk, StreamEnd, SynapsePacket, SynapseResponse, DEFAULT_MAX_FRAME_PAYLOAD,
};
use crate::util::unix_timestamp_secs;
use base64::{prelude::BASE64_STANDARD, Engine};
use quinn::{ClientConfig, Connection, Endpoint, IdleTimeout, TransportConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::ClientConfig as RustlsClientConfig;
use sp_core::{blake2_256, crypto::Ss58Codec, sr25519, Pair};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::Instant;
use tracing::{error, info, instrument, warn};

#[cfg(feature = "subtensor")]
use crate::metagraph::{Metagraph, MetagraphMonitorConfig};
#[cfg(feature = "subtensor")]
use subxt::{OnlineClient, PolkadotConfig};

#[derive(Clone)]
pub struct LightningClientConfig {
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub keep_alive_interval: Duration,
    pub reconnect_initial_backoff: Duration,
    pub reconnect_max_backoff: Duration,
    pub reconnect_max_retries: u32,
    pub max_connections: usize,
    pub max_frame_payload_bytes: usize,
    #[cfg(feature = "subtensor")]
    pub metagraph: Option<MetagraphMonitorConfig>,
}

impl Default for LightningClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(150),
            keep_alive_interval: Duration::from_secs(30),
            reconnect_initial_backoff: Duration::from_secs(1),
            reconnect_max_backoff: Duration::from_secs(60),
            reconnect_max_retries: 5,
            max_connections: 1024,
            max_frame_payload_bytes: DEFAULT_MAX_FRAME_PAYLOAD,
            #[cfg(feature = "subtensor")]
            metagraph: None,
        }
    }
}

struct ReconnectState {
    attempts: u32,
    next_retry_at: Instant,
}

struct ClientState {
    active_miners: HashMap<String, QuicAxonInfo>,
    established_connections: HashMap<String, Connection>,
    reconnect_states: HashMap<String, ReconnectState>,
    #[cfg(feature = "subtensor")]
    metagraph_shutdown: Option<tokio::sync::watch::Sender<bool>>,
    #[cfg(feature = "subtensor")]
    metagraph_handle: Option<tokio::task::JoinHandle<()>>,
}

pub struct StreamingResponse {
    recv: quinn::RecvStream,
    max_payload: usize,
}

impl StreamingResponse {
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        match read_frame(&mut self.recv, self.max_payload).await {
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
                    Err(LightningError::Stream(end.error.unwrap_or_else(|| {
                        "stream ended with failure status".to_string()
                    })))
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
            if total_size > self.max_payload {
                return Err(LightningError::Stream(format!(
                    "streaming response exceeded {} byte limit",
                    self.max_payload
                )));
            }
            chunks.push(chunk);
        }
        Ok(chunks)
    }
}

pub struct LightningClient {
    config: LightningClientConfig,
    wallet_hotkey: String,
    signer: Option<Arc<dyn Signer>>,
    state: Arc<RwLock<ClientState>>,
    endpoint: Option<Endpoint>,
}

impl LightningClient {
    pub fn new(wallet_hotkey: String) -> Self {
        Self::with_config(wallet_hotkey, LightningClientConfig::default())
            .expect("default config is always valid")
    }

    pub fn with_config(wallet_hotkey: String, config: LightningClientConfig) -> Result<Self> {
        if config.max_frame_payload_bytes < 1_048_576 {
            return Err(LightningError::Config(format!(
                "max_frame_payload_bytes ({}) must be at least 1048576 (1 MB)",
                config.max_frame_payload_bytes
            )));
        }
        if config.max_frame_payload_bytes > u32::MAX as usize {
            return Err(LightningError::Config(format!(
                "max_frame_payload_bytes ({}) must not exceed {} (u32::MAX)",
                config.max_frame_payload_bytes,
                u32::MAX
            )));
        }
        Ok(Self {
            config,
            wallet_hotkey,
            signer: None,
            state: Arc::new(RwLock::new(ClientState {
                active_miners: HashMap::new(),
                established_connections: HashMap::new(),
                reconnect_states: HashMap::new(),
                #[cfg(feature = "subtensor")]
                metagraph_shutdown: None,
                #[cfg(feature = "subtensor")]
                metagraph_handle: None,
            })),
            endpoint: None,
        })
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

    #[instrument(skip(self, miners), fields(miner_count = miners.len()))]
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

        let remaining_capacity = {
            let state = self.state.read().await;
            self.config
                .max_connections
                .saturating_sub(state.active_miners.len())
        };

        let miners = if miners.len() > remaining_capacity {
            warn!(
                "Connection limit ({}) reached with {} active, skipping {} of {} new miners",
                self.config.max_connections,
                self.config.max_connections - remaining_capacity,
                miners.len() - remaining_capacity,
                miners.len()
            );
            miners
                .into_iter()
                .take(remaining_capacity)
                .collect::<Vec<_>>()
        } else {
            miners
        };

        let max_fp = self.config.max_frame_payload_bytes;
        let mut set = tokio::task::JoinSet::new();
        for miner in miners {
            let ep = endpoint.clone();
            let wh = wallet_hotkey.clone();
            let s = signer.clone();
            set.spawn(async move {
                let miner_key = format!("{}:{}", miner.ip, miner.port);
                let result =
                    tokio::time::timeout(timeout, connect_and_handshake(ep, miner.clone(), wh, s, max_fp))
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

        let mut state = self.state.write().await;

        while let Some(join_result) = set.join_next().await {
            match join_result {
                Ok((miner_key, miner, result)) => match result {
                    Ok(connection) => {
                        state.active_miners.insert(miner_key.clone(), miner);
                        info!(
                            "Established persistent QUIC connection to miner: {}",
                            miner_key
                        );
                        state.established_connections.insert(miner_key, connection);
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

        #[cfg(feature = "subtensor")]
        if let Some(metagraph_config) = self.config.metagraph.take() {
            self.start_metagraph_monitor(metagraph_config).await?;
        }

        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn create_endpoint(&mut self) -> Result<()> {
        let mut tls_config = RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertVerifier))
            .with_no_client_auth();

        tls_config.alpn_protocols = vec![b"btlightning".to_vec()];

        let mut transport_config = TransportConfig::default();

        let idle_timeout = IdleTimeout::try_from(self.config.idle_timeout)
            .map_err(|e| LightningError::Config(format!("Failed to set idle timeout: {}", e)))?;
        transport_config.max_idle_timeout(Some(idle_timeout));
        transport_config.keep_alive_interval(Some(self.config.keep_alive_interval));

        let quic_crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).map_err(|e| {
                LightningError::Config(format!("Failed to create QUIC crypto config: {}", e))
            })?;
        let mut client_config = ClientConfig::new(Arc::new(quic_crypto));
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

    #[instrument(skip(self, axon_info, request), fields(miner_ip = %axon_info.ip, miner_port = axon_info.port))]
    pub async fn query_axon(
        &self,
        axon_info: QuicAxonInfo,
        request: QuicRequest,
    ) -> Result<QuicResponse> {
        let miner_key = format!("{}:{}", axon_info.ip, axon_info.port);

        let connection = {
            let state = self.state.read().await;
            state.established_connections.get(&miner_key).cloned()
        };

        let max_fp = self.config.max_frame_payload_bytes;
        match connection {
            Some(conn) if conn.close_reason().is_none() => {
                send_synapse_packet(&conn, request, max_fp).await
            }
            _ => {
                self.try_reconnect_and_query(&miner_key, &axon_info, request)
                    .await
            }
        }
    }

    #[instrument(skip(self, axon_info, request), fields(miner_ip = %axon_info.ip, miner_port = axon_info.port, timeout_ms = timeout.as_millis() as u64))]
    pub async fn query_axon_with_timeout(
        &self,
        axon_info: QuicAxonInfo,
        request: QuicRequest,
        timeout: Duration,
    ) -> Result<QuicResponse> {
        tokio::time::timeout(timeout, self.query_axon(axon_info, request))
            .await
            .map_err(|_| LightningError::Transport("query timed out".into()))?
    }

    #[instrument(skip(self, axon_info, request), fields(miner_ip = %axon_info.ip, miner_port = axon_info.port))]
    pub async fn query_axon_stream(
        &self,
        axon_info: QuicAxonInfo,
        request: QuicRequest,
    ) -> Result<StreamingResponse> {
        let miner_key = format!("{}:{}", axon_info.ip, axon_info.port);

        let connection = {
            let state = self.state.read().await;
            state.established_connections.get(&miner_key).cloned()
        };

        let max_fp = self.config.max_frame_payload_bytes;
        match connection {
            Some(conn) if conn.close_reason().is_none() => {
                open_streaming_synapse(&conn, request, max_fp).await
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
        send_synapse_packet(&connection, request, self.config.max_frame_payload_bytes).await
    }

    async fn try_reconnect_and_stream(
        &self,
        miner_key: &str,
        axon_info: &QuicAxonInfo,
        request: QuicRequest,
    ) -> Result<StreamingResponse> {
        let connection = self.try_reconnect(miner_key, axon_info).await?;
        open_streaming_synapse(&connection, request, self.config.max_frame_payload_bytes).await
    }

    // Intentional TOCTOU: read-lock reconnect_states for backoff check, drop before
    // network I/O (connect_and_handshake), then write-lock to update established_connections
    // and reconnect_states. This avoids holding a write lock across network calls at the cost
    // of allowing concurrent reconnections for the same miner_key — benign because the later
    // write simply overwrites the connection entry, wasting only redundant handshake work.
    async fn try_reconnect(&self, miner_key: &str, axon_info: &QuicAxonInfo) -> Result<Connection> {
        {
            let state = self.state.read().await;
            if let Some(rs) = state.reconnect_states.get(miner_key) {
                if rs.attempts >= self.config.reconnect_max_retries {
                    return Err(LightningError::Connection(format!(
                        "Reconnection attempts exhausted for {} ({}/{}), awaiting registry refresh",
                        miner_key, rs.attempts, self.config.reconnect_max_retries
                    )));
                }
                if Instant::now() < rs.next_retry_at {
                    return Err(LightningError::Connection(format!(
                        "Reconnection to {} in backoff, next retry in {:?}",
                        miner_key,
                        rs.next_retry_at - Instant::now()
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
                self.config.max_frame_payload_bytes,
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
                let mut state = self.state.write().await;
                state
                    .established_connections
                    .insert(miner_key.to_string(), connection.clone());
                state.reconnect_states.remove(miner_key);
                info!("Reconnected to miner {}", miner_key);
                Ok(connection)
            }
            Err(e) => {
                let mut state = self.state.write().await;
                let rs = state
                    .reconnect_states
                    .entry(miner_key.to_string())
                    .or_insert_with(|| ReconnectState {
                        attempts: 0,
                        next_retry_at: Instant::now(),
                    });
                rs.attempts += 1;
                let shift = rs.attempts.min(20);
                let backoff = (self.config.reconnect_initial_backoff * 2u32.pow(shift))
                    .min(self.config.reconnect_max_backoff);
                rs.next_retry_at = Instant::now() + backoff;
                error!(
                    "Reconnection to {} failed (attempt {}/{}), next retry in {:?}: {}",
                    miner_key, rs.attempts, self.config.reconnect_max_retries, backoff, e
                );
                Err(e)
            }
        }
    }

    #[instrument(skip(self, miners), fields(miner_count = miners.len()))]
    pub async fn update_miner_registry(&self, miners: Vec<QuicAxonInfo>) -> Result<()> {
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
        update_miner_registry_inner(
            &self.state,
            &endpoint,
            &self.wallet_hotkey,
            &signer,
            &self.config,
            miners,
        )
        .await
    }

    #[instrument(skip(self))]
    pub async fn get_connection_stats(&self) -> Result<HashMap<String, String>> {
        let state = self.state.read().await;

        let mut stats = HashMap::new();
        stats.insert(
            "total_connections".to_string(),
            state.established_connections.len().to_string(),
        );
        stats.insert(
            "active_miners".to_string(),
            state.active_miners.len().to_string(),
        );

        for key in state.active_miners.keys() {
            if state.established_connections.contains_key(key) {
                stats.insert(format!("connection_{}", key), "active".to_string());
            }
        }

        Ok(stats)
    }

    #[cfg(feature = "subtensor")]
    pub async fn start_metagraph_monitor(&self, monitor_config: MetagraphMonitorConfig) -> Result<()> {
        self.stop_metagraph_monitor().await;

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

        let subtensor = OnlineClient::<PolkadotConfig>::from_url(&monitor_config.subtensor_endpoint)
            .await
            .map_err(|e| LightningError::Handler(format!("connecting to subtensor: {}", e)))?;

        let mut metagraph = Metagraph::new(monitor_config.netuid);
        metagraph.sync(&subtensor).await?;

        let miners = metagraph.quic_miners();
        info!(
            netuid = monitor_config.netuid,
            miners = miners.len(),
            "initial metagraph sync complete"
        );

        update_miner_registry_inner(
            &self.state,
            &endpoint,
            &self.wallet_hotkey,
            &signer,
            &self.config,
            miners,
        )
        .await?;

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let state = self.state.clone();
        let wallet_hotkey = self.wallet_hotkey.clone();
        let mut config = self.config.clone();
        config.metagraph = None;
        let sync_interval = monitor_config.sync_interval;

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(sync_interval);
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = shutdown_rx.changed() => {
                        info!("metagraph monitor shutting down");
                        return;
                    }
                }

                match metagraph.sync(&subtensor).await {
                    Ok(()) => {
                        let miners = metagraph.quic_miners();
                        info!(
                            netuid = metagraph.netuid,
                            miners = miners.len(),
                            block = metagraph.block,
                            "metagraph resync complete"
                        );
                        if let Err(e) = update_miner_registry_inner(
                            &state,
                            &endpoint,
                            &wallet_hotkey,
                            &signer,
                            &config,
                            miners,
                        )
                        .await
                        {
                            error!("registry update after metagraph sync failed: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("metagraph sync failed: {}", e);
                    }
                }
            }
        });

        let mut st = self.state.write().await;
        st.metagraph_shutdown = Some(shutdown_tx);
        st.metagraph_handle = Some(handle);
        Ok(())
    }

    #[cfg(feature = "subtensor")]
    pub async fn stop_metagraph_monitor(&self) {
        let (shutdown_tx, handle) = {
            let mut st = self.state.write().await;
            (st.metagraph_shutdown.take(), st.metagraph_handle.take())
        };
        if let Some(tx) = shutdown_tx {
            let _ = tx.send(true);
        }
        if let Some(mut handle) = handle {
            if tokio::time::timeout(Duration::from_secs(5), &mut handle).await.is_err() {
                warn!("metagraph monitor did not shut down within 5s, aborting");
                handle.abort();
            }
        }
    }

    #[instrument(skip(self))]
    pub async fn close_all_connections(&self) -> Result<()> {
        #[cfg(feature = "subtensor")]
        self.stop_metagraph_monitor().await;

        let mut state = self.state.write().await;

        for (_, connection) in state.established_connections.drain() {
            connection.close(0u32.into(), b"client_shutdown");
        }

        state.active_miners.clear();
        state.reconnect_states.clear();

        info!("All Lightning QUIC connections closed");
        Ok(())
    }
}

async fn update_miner_registry_inner(
    state: &Arc<RwLock<ClientState>>,
    endpoint: &Endpoint,
    wallet_hotkey: &str,
    signer: &Arc<dyn Signer>,
    config: &LightningClientConfig,
    miners: Vec<QuicAxonInfo>,
) -> Result<()> {
    let current_miners: HashMap<String, QuicAxonInfo> = miners
        .iter()
        .map(|m| (format!("{}:{}", m.ip, m.port), m.clone()))
        .collect();

    let new_miner_keys: Vec<(String, QuicAxonInfo)>;
    {
        let mut st = state.write().await;

        let active_keys: Vec<String> = st.active_miners.keys().cloned().collect();
        for key in active_keys {
            if !current_miners.contains_key(&key) {
                info!("Miner deregistered, closing QUIC connection: {}", key);
                if let Some(connection) = st.established_connections.remove(&key) {
                    connection.close(0u32.into(), b"miner_deregistered");
                }
                st.active_miners.remove(&key);
                st.reconnect_states.remove(&key);
            }
        }

        for key in current_miners.keys() {
            if st.reconnect_states.remove(key).is_some() {
                info!("Registry refresh reset reconnection backoff for {}", key);
            }
        }

        let remaining_capacity = config
            .max_connections
            .saturating_sub(st.active_miners.len());
        let eligible: Vec<(String, QuicAxonInfo)> = current_miners
            .into_iter()
            .filter(|(key, _)| !st.active_miners.contains_key(key))
            .collect();

        if eligible.len() > remaining_capacity {
            warn!(
                "Connection limit ({}) reached, skipping {} of {} new miners",
                config.max_connections,
                eligible.len() - remaining_capacity,
                eligible.len()
            );
        }

        new_miner_keys = eligible.into_iter().take(remaining_capacity).collect();

        for (key, miner) in &new_miner_keys {
            st.active_miners.insert(key.clone(), miner.clone());
        }
    }

    if !new_miner_keys.is_empty() {
        let timeout = config.connect_timeout;
        let max_fp = config.max_frame_payload_bytes;

        let pending_keys: Vec<String> = new_miner_keys.iter().map(|(k, _)| k.clone()).collect();
        let mut set = tokio::task::JoinSet::new();
        for (key, miner) in new_miner_keys {
            info!("New miner detected, establishing QUIC connection: {}", key);
            let ep = endpoint.clone();
            let wh = wallet_hotkey.to_string();
            let s = signer.clone();
            set.spawn(async move {
                let result = tokio::time::timeout(
                    timeout,
                    connect_and_handshake(ep, miner.clone(), wh, s, max_fp),
                )
                .await;
                let result = match result {
                    Ok(r) => r,
                    Err(_) => Err(LightningError::Connection(format!(
                        "Connection to {} timed out",
                        key
                    ))),
                };
                (key, result)
            });
        }

        let mut results = Vec::new();
        while let Some(join_result) = set.join_next().await {
            match join_result {
                Ok(result) => results.push(result),
                Err(e) => {
                    error!("Connection task panicked: {}", e);
                }
            }
        }

        let mut st = state.write().await;
        for (key, result) in results {
            match result {
                Ok(connection) => {
                    st.established_connections.insert(key, connection);
                }
                Err(e) => {
                    error!("Failed to connect to new miner {}: {}", key, e);
                    st.active_miners.remove(&key);
                }
            }
        }

        for key in &pending_keys {
            if !st.established_connections.contains_key(key) {
                st.active_miners.remove(key);
            }
        }
    }

    Ok(())
}

fn get_peer_cert_fingerprint(connection: &Connection) -> Option<[u8; 32]> {
    let identity = connection.peer_identity()?;
    let certs = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    let first = certs.first()?;
    Some(blake2_256(first.as_ref()))
}

async fn connect_and_handshake(
    endpoint: Endpoint,
    miner: QuicAxonInfo,
    wallet_hotkey: String,
    signer: Arc<dyn Signer>,
    max_frame_payload: usize,
) -> Result<Connection> {
    let addr: SocketAddr = format!("{}:{}", miner.ip, miner.port)
        .parse()
        .map_err(|e| LightningError::Connection(format!("Invalid address: {}", e)))?;

    let connection = endpoint
        .connect(addr, &miner.ip)
        .map_err(|e| LightningError::Connection(format!("Connection failed: {}", e)))?
        .await
        .map_err(|e| LightningError::Connection(format!("Connection handshake failed: {}", e)))?;

    let peer_cert_fp = get_peer_cert_fingerprint(&connection).ok_or_else(|| {
        LightningError::Handshake("peer certificate not available for fingerprinting".to_string())
    })?;
    let peer_cert_fp_b64 = BASE64_STANDARD.encode(peer_cert_fp);

    let nonce = generate_nonce();
    let timestamp = unix_timestamp_secs();
    let message = handshake_request_message(&wallet_hotkey, timestamp, &nonce, &peer_cert_fp_b64);
    let msg_bytes = message.into_bytes();
    let signer_clone = signer.clone();
    let signature_bytes = tokio::task::spawn_blocking(move || signer_clone.sign(&msg_bytes))
        .await
        .map_err(|e| LightningError::Signing(format!("signer task failed: {}", e)))??;

    let handshake_request = HandshakeRequest {
        validator_hotkey: wallet_hotkey.clone(),
        timestamp,
        nonce: nonce.clone(),
        signature: BASE64_STANDARD.encode(&signature_bytes),
    };

    let response = send_handshake(&connection, handshake_request, max_frame_payload).await?;
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

    let expected_message = handshake_response_message(
        validator_hotkey,
        &response.miner_hotkey,
        response.timestamp,
        nonce,
        cert_fp_b64,
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
    max_frame_payload: usize,
) -> Result<HandshakeResponse> {
    let (mut send, mut recv) = connection.open_bi().await.map_err(|e| {
        LightningError::Connection(format!("Failed to open bidirectional stream: {}", e))
    })?;

    let request_bytes = rmp_serde::to_vec(&request).map_err(|e| {
        LightningError::Serialization(format!("Failed to serialize handshake: {}", e))
    })?;

    write_frame_and_finish(&mut send, MessageType::HandshakeRequest, &request_bytes).await?;

    let (msg_type, payload) = read_frame(&mut recv, max_frame_payload).await?;
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
    max_frame_payload: usize,
) -> Result<QuicResponse> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| LightningError::Connection(format!("Failed to open stream: {}", e)))?;

    let start = Instant::now();

    send_synapse_frame(&mut send, request).await?;

    let (msg_type, payload) = read_frame(&mut recv, max_frame_payload).await?;

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
                error: synapse_response.error,
            })
        }
        MessageType::StreamChunk => Err(LightningError::Transport(
            "received StreamChunk on non-streaming query; use query_axon_stream for streaming synapses".to_string(),
        )),
        other => Err(LightningError::Transport(format!(
            "unexpected response type: {:?}",
            other
        ))),
    }
}

async fn open_streaming_synapse(
    connection: &Connection,
    request: QuicRequest,
    max_frame_payload: usize,
) -> Result<StreamingResponse> {
    let (mut send, recv) = connection
        .open_bi()
        .await
        .map_err(|e| LightningError::Connection(format!("Failed to open stream: {}", e)))?;

    send_synapse_frame(&mut send, request).await?;

    Ok(StreamingResponse { recv, max_payload: max_frame_payload })
}

fn generate_nonce() -> String {
    use rand::Rng;
    let bytes: [u8; 16] = rand::thread_rng().gen();
    format!("{:032x}", u128::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_core::crypto::Ss58Codec;

    const MINER_SEED: [u8; 32] = [1u8; 32];
    const VALIDATOR_SEED: [u8; 32] = [2u8; 32];

    fn make_signed_response(
        miner_seed: [u8; 32],
        validator_hotkey: &str,
        nonce: &str,
        cert_fp_b64: &str,
    ) -> HandshakeResponse {
        let pair = sr25519::Pair::from_seed(&miner_seed);
        let miner_hotkey = pair.public().to_ss58check();
        let timestamp = unix_timestamp_secs();
        let message = handshake_response_message(
            validator_hotkey,
            &miner_hotkey,
            timestamp,
            nonce,
            cert_fp_b64,
        );
        let signature = pair.sign(message.as_bytes());
        HandshakeResponse {
            miner_hotkey,
            timestamp,
            signature: BASE64_STANDARD.encode(signature.0),
            accepted: true,
            connection_id: "test".to_string(),
            cert_fingerprint: Some(cert_fp_b64.to_string()),
        }
    }

    fn validator_hotkey() -> String {
        sr25519::Pair::from_seed(&VALIDATOR_SEED)
            .public()
            .to_ss58check()
    }

    #[tokio::test]
    async fn verify_valid_miner_signature() {
        let nonce = "test-nonce";
        let fp = "dGVzdC1mcA==";
        let resp = make_signed_response(MINER_SEED, &validator_hotkey(), nonce, fp);
        assert!(
            verify_miner_response_signature(&resp, &validator_hotkey(), nonce, fp)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn verify_rejects_empty_signature() {
        let mut resp = make_signed_response(MINER_SEED, &validator_hotkey(), "n", "fp");
        resp.signature = String::new();
        let err = verify_miner_response_signature(&resp, &validator_hotkey(), "n", "fp")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("empty signature"));
    }

    #[tokio::test]
    async fn verify_rejects_invalid_base64() {
        let mut resp = make_signed_response(MINER_SEED, &validator_hotkey(), "n", "fp");
        resp.signature = "not-valid-base64!!!".to_string();
        let err = verify_miner_response_signature(&resp, &validator_hotkey(), "n", "fp")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("decode miner signature"));
    }

    #[tokio::test]
    async fn verify_rejects_wrong_signature_length() {
        let mut resp = make_signed_response(MINER_SEED, &validator_hotkey(), "n", "fp");
        resp.signature = BASE64_STANDARD.encode([0u8; 32]);
        let err = verify_miner_response_signature(&resp, &validator_hotkey(), "n", "fp")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Invalid miner signature length"));
    }

    #[tokio::test]
    async fn verify_rejects_bad_ss58_address() {
        let mut resp = make_signed_response(MINER_SEED, &validator_hotkey(), "n", "fp");
        resp.miner_hotkey = "not_a_valid_ss58".to_string();
        let err = verify_miner_response_signature(&resp, &validator_hotkey(), "n", "fp")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Invalid miner SS58 address"));
    }

    #[tokio::test]
    async fn verify_rejects_wrong_signer() {
        let nonce = "n";
        let fp = "fp";
        let mut resp = make_signed_response(MINER_SEED, &validator_hotkey(), nonce, fp);
        let wrong_pair = sr25519::Pair::from_seed(&[99u8; 32]);
        resp.miner_hotkey = wrong_pair.public().to_ss58check();
        let err = verify_miner_response_signature(&resp, &validator_hotkey(), nonce, fp)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
    }

    #[tokio::test]
    async fn verify_rejects_tampered_nonce() {
        let fp = "fp";
        let resp = make_signed_response(MINER_SEED, &validator_hotkey(), "original-nonce", fp);
        let err = verify_miner_response_signature(&resp, &validator_hotkey(), "tampered-nonce", fp)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
    }
}

// Deliberately disables TLS PKI certificate validation. TLS still provides transport
// encryption but not identity authentication. Authenticity is instead enforced at the
// application layer: the handshake exchanges certificate fingerprints and verifies
// sr25519 signatures over them (see connect_and_handshake / process_handshake).
#[derive(Debug)]
struct AcceptAnyCertVerifier;

impl ServerCertVerifier for AcceptAnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
