use pyo3::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::to_pyerr;
use crate::extraction::stats_to_py;
use crate::handler::{PythonStreamingSynapseHandler, PythonSynapseHandler};
use crate::set_opt;
use crate::signer::PythonPermitResolver;

#[pyclass]
pub struct RustLightningServer {
    server: RwLock<btlightning::LightningServer>,
    runtime: Arc<tokio::runtime::Runtime>,
}

#[pymethods]
impl RustLightningServer {
    #[new]
    #[pyo3(signature = (
        miner_hotkey,
        host,
        port,
        max_signature_age_secs=None,
        idle_timeout_secs=None,
        keep_alive_interval_secs=None,
        nonce_cleanup_interval_secs=None,
        max_connections=None,
        max_nonce_entries=None,
        handshake_timeout_secs=None,
        max_handshake_attempts_per_minute=None,
        max_concurrent_bidi_streams=None,
        require_validator_permit=None,
        validator_permit_refresh_secs=None,
        handler_timeout_secs=None,
        max_frame_payload_bytes=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        miner_hotkey: String,
        host: String,
        port: u16,
        max_signature_age_secs: Option<u64>,
        idle_timeout_secs: Option<u64>,
        keep_alive_interval_secs: Option<u64>,
        nonce_cleanup_interval_secs: Option<u64>,
        max_connections: Option<usize>,
        max_nonce_entries: Option<usize>,
        handshake_timeout_secs: Option<u64>,
        max_handshake_attempts_per_minute: Option<u32>,
        max_concurrent_bidi_streams: Option<u32>,
        require_validator_permit: Option<bool>,
        validator_permit_refresh_secs: Option<u64>,
        handler_timeout_secs: Option<u64>,
        max_frame_payload_bytes: Option<usize>,
    ) -> PyResult<Self> {
        let runtime = Arc::new(tokio::runtime::Runtime::new().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to create async runtime: {}",
                e
            ))
        })?);

        let mut config = btlightning::LightningServerConfig::default();
        set_opt!(config, max_signature_age_secs, max_signature_age_secs);
        set_opt!(config, idle_timeout_secs, idle_timeout_secs);
        set_opt!(config, keep_alive_interval_secs, keep_alive_interval_secs);
        set_opt!(
            config,
            nonce_cleanup_interval_secs,
            nonce_cleanup_interval_secs
        );
        set_opt!(config, max_connections, max_connections);
        set_opt!(config, max_nonce_entries, max_nonce_entries);
        set_opt!(config, handshake_timeout_secs, handshake_timeout_secs);
        set_opt!(
            config,
            max_handshake_attempts_per_minute,
            max_handshake_attempts_per_minute
        );
        set_opt!(
            config,
            max_concurrent_bidi_streams,
            max_concurrent_bidi_streams
        );
        set_opt!(config, require_validator_permit, require_validator_permit);
        set_opt!(
            config,
            validator_permit_refresh_secs,
            validator_permit_refresh_secs
        );
        set_opt!(config, handler_timeout_secs, handler_timeout_secs);
        set_opt!(config, max_frame_payload_bytes, max_frame_payload_bytes);

        let server = btlightning::LightningServer::with_config(miner_hotkey, host, port, config)
            .map_err(to_pyerr)?;

        Ok(Self {
            server: RwLock::new(server),
            runtime,
        })
    }

    pub fn set_miner_keypair(&self, py: Python<'_>, keypair_seed: [u8; 32]) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        py.detach(|| {
            runtime.block_on(async {
                let mut server = self.server.write().await;
                server.set_miner_keypair(keypair_seed);
            })
        });
        Ok(())
    }

    pub fn set_miner_wallet(
        &self,
        py: Python<'_>,
        wallet_name: String,
        wallet_path: String,
        hotkey_name: String,
    ) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        py.detach(|| {
            runtime.block_on(async {
                let mut server = self.server.write().await;
                server.set_miner_wallet(&wallet_name, &wallet_path, &hotkey_name)
            })
        })
        .map_err(to_pyerr)
    }

    pub fn set_validator_permit_resolver(
        &self,
        py: Python<'_>,
        resolver_callback: Py<PyAny>,
    ) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        py.detach(|| {
            runtime.block_on(async {
                let mut server = self.server.write().await;
                server.set_validator_permit_resolver(Box::new(PythonPermitResolver::new(
                    resolver_callback,
                )));
            })
        });
        Ok(())
    }

    pub fn register_synapse_handler(
        &self,
        py: Python<'_>,
        synapse_type: String,
        handler: Py<PyAny>,
    ) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        py.detach(|| {
            runtime.block_on(async {
                let server = self.server.read().await;
                server
                    .register_synapse_handler(
                        synapse_type,
                        Arc::new(PythonSynapseHandler::new(handler)),
                    )
                    .await
            })
        })
        .map_err(to_pyerr)
    }

    pub fn register_streaming_handler(
        &self,
        py: Python<'_>,
        synapse_type: String,
        handler: Py<PyAny>,
    ) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        py.detach(|| {
            runtime.block_on(async {
                let server = self.server.read().await;
                server
                    .register_streaming_handler(
                        synapse_type,
                        Arc::new(PythonStreamingSynapseHandler::new(handler)),
                    )
                    .await
            })
        })
        .map_err(to_pyerr)
    }

    pub fn start(&self, py: Python<'_>) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        py.detach(|| {
            runtime.block_on(async {
                let mut server = self.server.write().await;
                server.start().await
            })
        })
        .map_err(to_pyerr)
    }

    pub fn serve_forever(&self, py: Python<'_>) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        py.detach(|| {
            runtime.block_on(async {
                let server = self.server.read().await;
                server.serve_forever().await
            })
        })
        .map_err(to_pyerr)
    }

    pub fn get_connection_stats(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let runtime = Arc::clone(&self.runtime);
        let stats = py
            .detach(|| {
                runtime.block_on(async {
                    let server = self.server.read().await;
                    server.get_connection_stats().await
                })
            })
            .map_err(to_pyerr)?;

        stats_to_py(py, stats)
    }

    pub fn cleanup_stale_connections(&self, py: Python<'_>, max_idle_seconds: u64) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        py.detach(|| {
            runtime.block_on(async {
                let server = self.server.read().await;
                server.cleanup_stale_connections(max_idle_seconds).await
            })
        })
        .map_err(to_pyerr)
    }

    pub fn stop(&self, py: Python<'_>) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        py.detach(|| {
            runtime.block_on(async {
                let server = self.server.read().await;
                server.stop().await
            })
        })
        .map_err(to_pyerr)
    }
}
