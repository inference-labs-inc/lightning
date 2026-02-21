use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

mod handler;
mod signer;
mod types;

use handler::{
    msgpack_value_to_py, py_to_msgpack_value, PythonStreamingSynapseHandler, PythonSynapseHandler,
};
use signer::{PythonPermitResolver, PythonSigner};
use types::PyQuicAxonInfo;

fn to_pyerr(err: btlightning::LightningError) -> PyErr {
    match err {
        btlightning::LightningError::Connection(msg) => {
            PyErr::new::<pyo3::exceptions::PyConnectionError, _>(format!(
                "connection error: {}",
                msg
            ))
        }
        btlightning::LightningError::Handshake(msg) => {
            PyErr::new::<pyo3::exceptions::PyConnectionError, _>(format!(
                "handshake error: {}",
                msg
            ))
        }
        btlightning::LightningError::Config(msg) => {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("config error: {}", msg))
        }
        btlightning::LightningError::Serialization(msg) => {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("serialization error: {}", msg))
        }
        btlightning::LightningError::Transport(msg) => {
            PyErr::new::<pyo3::exceptions::PyConnectionError, _>(format!(
                "transport error: {}",
                msg
            ))
        }
        btlightning::LightningError::Signing(msg) => {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("signing error: {}", msg))
        }
        btlightning::LightningError::Handler(msg) => {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("handler error: {}", msg))
        }
        btlightning::LightningError::Stream(msg) => {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("stream error: {}", msg))
        }
    }
}

#[pyclass]
pub struct PyStreamingResponse {
    response: Arc<tokio::sync::Mutex<btlightning::StreamingResponse>>,
    runtime: Arc<tokio::runtime::Runtime>,
}

#[pymethods]
impl PyStreamingResponse {
    fn __iter__(slf: PyRef<Self>) -> PyRef<Self> {
        slf
    }

    fn __next__(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        let response = self.response.clone();
        let runtime = self.runtime.clone();
        let result = py.detach(|| {
            runtime.block_on(async {
                let mut resp = response.lock().await;
                resp.next_chunk().await
            })
        });
        match result {
            Ok(Some(bytes)) => Ok(Some(PyBytes::new(py, &bytes).into_any().unbind())),
            Ok(None) => Ok(None),
            Err(e) => Err(to_pyerr(e)),
        }
    }
}

#[pyclass]
pub struct RustLightning {
    client: RwLock<btlightning::LightningClient>,
    runtime: Arc<tokio::runtime::Runtime>,
}

#[pymethods]
impl RustLightning {
    #[new]
    #[pyo3(signature = (
        wallet_hotkey,
        connect_timeout_secs=None,
        idle_timeout_secs=None,
        keep_alive_interval_secs=None,
        reconnect_initial_backoff_secs=None,
        reconnect_max_backoff_secs=None,
        reconnect_max_retries=None,
        max_connections=None,
        max_frame_payload_bytes=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_hotkey: String,
        connect_timeout_secs: Option<u64>,
        idle_timeout_secs: Option<u64>,
        keep_alive_interval_secs: Option<u64>,
        reconnect_initial_backoff_secs: Option<u64>,
        reconnect_max_backoff_secs: Option<u64>,
        reconnect_max_retries: Option<u32>,
        max_connections: Option<usize>,
        max_frame_payload_bytes: Option<usize>,
    ) -> PyResult<Self> {
        let runtime = Arc::new(tokio::runtime::Runtime::new().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to create async runtime: {}",
                e
            ))
        })?);

        let mut config = btlightning::LightningClientConfig::default();
        if let Some(v) = connect_timeout_secs {
            config.connect_timeout = Duration::from_secs(v);
        }
        if let Some(v) = idle_timeout_secs {
            config.idle_timeout = Duration::from_secs(v);
        }
        if let Some(v) = keep_alive_interval_secs {
            config.keep_alive_interval = Duration::from_secs(v);
        }
        if let Some(v) = reconnect_initial_backoff_secs {
            config.reconnect_initial_backoff = Duration::from_secs(v);
        }
        if let Some(v) = reconnect_max_backoff_secs {
            config.reconnect_max_backoff = Duration::from_secs(v);
        }
        if let Some(v) = reconnect_max_retries {
            config.reconnect_max_retries = v;
        }
        if let Some(v) = max_connections {
            config.max_connections = v;
        }
        if let Some(v) = max_frame_payload_bytes {
            config.max_frame_payload_bytes = v;
        }

        let client = btlightning::LightningClient::with_config(wallet_hotkey, config)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        Ok(Self {
            client: RwLock::new(client),
            runtime,
        })
    }

    pub fn set_validator_keypair(&self, py: Python<'_>, keypair_seed: [u8; 32]) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        py.detach(|| {
            runtime.block_on(async {
                let mut client = self.client.write().await;
                client.set_signer(Box::new(btlightning::Sr25519Signer::from_seed(
                    keypair_seed,
                )));
            })
        });
        Ok(())
    }

    pub fn set_python_signer(&self, py: Python<'_>, signer_callback: Py<PyAny>) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        py.detach(|| {
            runtime.block_on(async {
                let mut client = self.client.write().await;
                client.set_signer(Box::new(PythonSigner::new(signer_callback)));
            })
        });
        Ok(())
    }

    pub fn set_wallet(
        &self,
        py: Python<'_>,
        wallet_name: String,
        wallet_path: String,
        hotkey_name: String,
    ) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        py.detach(|| {
            runtime.block_on(async {
                let mut client = self.client.write().await;
                client.set_wallet(&wallet_name, &wallet_path, &hotkey_name)
            })
        })
        .map_err(to_pyerr)
    }

    pub fn initialize_connections(&self, py: Python<'_>, miners: Vec<Py<PyAny>>) -> PyResult<()> {
        let mut quic_miners = Vec::new();
        for miner_obj in miners {
            quic_miners.push(extract_quic_axon_info(py, &miner_obj)?);
        }

        let runtime = Arc::clone(&self.runtime);
        py.detach(|| {
            runtime.block_on(async {
                let mut client = self.client.write().await;
                client.initialize_connections(quic_miners).await
            })
        })
        .map_err(to_pyerr)
    }

    #[pyo3(signature = (axon_data, request_data, timeout_secs=None))]
    pub fn query_axon(
        &self,
        py: Python<'_>,
        axon_data: Py<PyAny>,
        request_data: Py<PyAny>,
        timeout_secs: Option<f64>,
    ) -> PyResult<Py<PyAny>> {
        let axon_info = extract_quic_axon_info(py, &axon_data)?;
        let request = extract_quic_request(py, &request_data)?;

        let runtime = Arc::clone(&self.runtime);
        let response = py
            .detach(|| {
                runtime.block_on(async {
                    let client = self.client.read().await;
                    match timeout_secs {
                        Some(t) => {
                            const MAX_TIMEOUT_SECS: f64 = u64::MAX as f64;
                            if !t.is_finite() || !(0.0..=MAX_TIMEOUT_SECS).contains(&t) {
                                return Err(btlightning::LightningError::Config(format!(
                                    "timeout_secs must be a finite non-negative number, got {t}"
                                )));
                            }
                            client
                                .query_axon_with_timeout(
                                    axon_info,
                                    request,
                                    Duration::from_secs_f64(t),
                                )
                                .await
                        }
                        None => client.query_axon(axon_info, request).await,
                    }
                })
            })
            .map_err(to_pyerr)?;

        let result_dict = PyDict::new(py);
        let data_dict = PyDict::new(py);
        for (key, value) in &response.data {
            let py_value = msgpack_value_to_py(py, value)?;
            data_dict.set_item(key, py_value)?;
        }
        result_dict.set_item("data", data_dict)?;
        result_dict.set_item("success", response.success)?;
        result_dict.set_item("latency_ms", response.latency_ms)?;
        match &response.error {
            Some(e) => result_dict.set_item("error", e)?,
            None => result_dict.set_item("error", py.None())?,
        }

        Ok(result_dict.into_any().unbind())
    }

    pub fn query_axon_stream(
        &self,
        py: Python<'_>,
        axon_data: Py<PyAny>,
        request_data: Py<PyAny>,
    ) -> PyResult<PyStreamingResponse> {
        let axon_info = extract_quic_axon_info(py, &axon_data)?;
        let request = extract_quic_request(py, &request_data)?;

        let runtime = Arc::clone(&self.runtime);
        let streaming_response = py
            .detach(|| {
                runtime.block_on(async {
                    let client = self.client.read().await;
                    client.query_axon_stream(axon_info, request).await
                })
            })
            .map_err(to_pyerr)?;

        Ok(PyStreamingResponse {
            response: Arc::new(tokio::sync::Mutex::new(streaming_response)),
            runtime: Arc::clone(&self.runtime),
        })
    }

    pub fn update_miner_registry(&self, py: Python<'_>, miners: Vec<Py<PyAny>>) -> PyResult<()> {
        let mut quic_miners = Vec::new();
        for miner_obj in miners {
            quic_miners.push(extract_quic_axon_info(py, &miner_obj)?);
        }

        let runtime = Arc::clone(&self.runtime);
        py.detach(|| {
            runtime.block_on(async {
                let client = self.client.read().await;
                client.update_miner_registry(quic_miners).await
            })
        })
        .map_err(to_pyerr)
    }

    pub fn get_connection_stats(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let runtime = Arc::clone(&self.runtime);
        let stats = py
            .detach(|| {
                runtime.block_on(async {
                    let client = self.client.read().await;
                    client.get_connection_stats().await
                })
            })
            .map_err(to_pyerr)?;

        let result_dict = PyDict::new(py);
        for (key, value) in stats {
            result_dict.set_item(key, value)?;
        }
        Ok(result_dict.into_any().unbind())
    }

    pub fn close_all_connections(&self, py: Python<'_>) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        py.detach(|| {
            runtime.block_on(async {
                let client = self.client.read().await;
                client.close_all_connections().await
            })
        })
        .map_err(to_pyerr)
    }
}

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
        if let Some(v) = max_signature_age_secs {
            config.max_signature_age_secs = v;
        }
        if let Some(v) = idle_timeout_secs {
            config.idle_timeout_secs = v;
        }
        if let Some(v) = keep_alive_interval_secs {
            config.keep_alive_interval_secs = v;
        }
        if let Some(v) = nonce_cleanup_interval_secs {
            config.nonce_cleanup_interval_secs = v;
        }
        if let Some(v) = max_connections {
            config.max_connections = v;
        }
        if let Some(v) = max_nonce_entries {
            config.max_nonce_entries = v;
        }
        if let Some(v) = handshake_timeout_secs {
            config.handshake_timeout_secs = v;
        }
        if let Some(v) = max_handshake_attempts_per_minute {
            config.max_handshake_attempts_per_minute = v;
        }
        if let Some(v) = max_concurrent_bidi_streams {
            config.max_concurrent_bidi_streams = v;
        }
        if let Some(v) = require_validator_permit {
            config.require_validator_permit = v;
        }
        if let Some(v) = validator_permit_refresh_secs {
            config.validator_permit_refresh_secs = v;
        }
        if let Some(v) = handler_timeout_secs {
            config.handler_timeout_secs = v;
        }
        if let Some(v) = max_frame_payload_bytes {
            config.max_frame_payload_bytes = v;
        }

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

        let result_dict = PyDict::new(py);
        for (key, value) in stats {
            result_dict.set_item(key, value)?;
        }
        Ok(result_dict.into_any().unbind())
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

fn extract_quic_request(
    py: Python,
    request_data: &Py<pyo3::PyAny>,
) -> PyResult<btlightning::QuicRequest> {
    let request_dict = request_data.extract::<HashMap<String, Py<pyo3::PyAny>>>(py)?;

    let synapse_type = request_dict
        .get("synapse_type")
        .ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyKeyError, _>("Missing 'synapse_type' field")
        })?
        .extract::<String>(py)?;

    let mut data = HashMap::new();
    if let Some(data_obj) = request_dict.get("data") {
        let data_dict = data_obj.extract::<HashMap<String, Py<pyo3::PyAny>>>(py)?;
        for (key, value) in data_dict {
            let val = value.bind(py);
            let msgpack_value = py_to_msgpack_value(val).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Failed to convert Python value to msgpack: {}",
                    e
                ))
            })?;
            data.insert(key, msgpack_value);
        }
    }

    Ok(btlightning::QuicRequest::new(synapse_type, data))
}

fn extract_quic_axon_info(
    py: Python,
    miner_obj: &Py<pyo3::PyAny>,
) -> PyResult<btlightning::QuicAxonInfo> {
    let miner_dict = miner_obj.extract::<HashMap<String, Py<pyo3::PyAny>>>(py)?;

    let hotkey = miner_dict
        .get("hotkey")
        .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("Missing 'hotkey' field"))?
        .extract::<String>(py)?;

    let ip = miner_dict
        .get("ip")
        .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("Missing 'ip' field"))?
        .extract::<String>(py)?;

    let port = miner_dict
        .get("port")
        .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("Missing 'port' field"))?
        .extract::<u16>(py)?;

    let protocol = miner_dict
        .get("protocol")
        .map(|p| p.extract::<u8>(py))
        .transpose()?
        .unwrap_or(4);
    let placeholder1 = miner_dict
        .get("placeholder1")
        .map(|p| p.extract::<u8>(py))
        .transpose()?
        .unwrap_or(0);
    let placeholder2 = miner_dict
        .get("placeholder2")
        .map(|p| p.extract::<u8>(py))
        .transpose()?
        .unwrap_or(0);

    Ok(btlightning::QuicAxonInfo::new(
        hotkey,
        ip,
        port,
        protocol,
        placeholder1,
        placeholder2,
    ))
}

#[pymodule]
fn _native(m: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
    m.add_class::<RustLightning>()?;
    m.add_class::<RustLightningServer>()?;
    m.add_class::<PyStreamingResponse>()?;
    m.add_class::<PyQuicAxonInfo>()?;
    Ok(())
}
