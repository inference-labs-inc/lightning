use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::error::to_pyerr;
use crate::extraction::{
    extract_quic_axon_info, extract_quic_request, response_to_py, stats_to_py,
};
use crate::set_opt;
use crate::signer::PythonSigner;

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
        max_stream_payload_bytes=None,
        stream_chunk_timeout_secs=None,
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
        max_stream_payload_bytes: Option<usize>,
        stream_chunk_timeout_secs: Option<u64>,
    ) -> PyResult<Self> {
        let runtime = Arc::new(tokio::runtime::Runtime::new().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to create async runtime: {}",
                e
            ))
        })?);

        let mut config = btlightning::LightningClientConfig::default();
        set_opt!(config, connect_timeout, connect_timeout_secs, secs);
        set_opt!(config, idle_timeout, idle_timeout_secs, secs);
        set_opt!(config, keep_alive_interval, keep_alive_interval_secs, secs);
        set_opt!(
            config,
            reconnect_initial_backoff,
            reconnect_initial_backoff_secs,
            secs
        );
        set_opt!(
            config,
            reconnect_max_backoff,
            reconnect_max_backoff_secs,
            secs
        );
        set_opt!(config, reconnect_max_retries, reconnect_max_retries);
        set_opt!(config, max_connections, max_connections);
        set_opt!(config, max_frame_payload_bytes, max_frame_payload_bytes);
        set_opt!(config, max_stream_payload_bytes, max_stream_payload_bytes);
        if let Some(v) = stream_chunk_timeout_secs.filter(|&v| v > 0) {
            config.stream_chunk_timeout = Some(Duration::from_secs(v));
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
                            const MAX_TIMEOUT_SECS: f64 = 315_360_000.0;
                            if !t.is_finite()
                                || !(f64::MIN_POSITIVE..=MAX_TIMEOUT_SECS).contains(&t)
                            {
                                return Err(btlightning::LightningError::Config(format!(
                                    "timeout_secs must be a finite positive number, got {t}"
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

        response_to_py(py, &response)
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

        stats_to_py(py, stats)
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
