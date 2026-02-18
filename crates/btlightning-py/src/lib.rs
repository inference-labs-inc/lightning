#![allow(non_local_definitions)]

use pyo3::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

mod handler;
mod signer;
mod types;

use handler::PythonSynapseHandler;
use signer::PythonSigner;
use types::PyQuicAxonInfo;

fn to_pyerr(err: btlightning::LightningError) -> PyErr {
    match err {
        btlightning::LightningError::Connection(msg) => {
            PyErr::new::<pyo3::exceptions::PyConnectionError, _>(msg)
        }
        btlightning::LightningError::Config(msg) => {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(msg)
        }
        btlightning::LightningError::Signing(msg) => {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("signing error: {}", msg))
        }
        btlightning::LightningError::Handler(msg) => {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("handler error: {}", msg))
        }
        _ => PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(err.to_string()),
    }
}

#[pyclass]
pub struct RustLightning {
    client: Mutex<btlightning::LightningClient>,
    runtime: Arc<tokio::runtime::Runtime>,
}

#[pymethods]
impl RustLightning {
    #[new]
    pub fn new(wallet_hotkey: String) -> PyResult<Self> {
        let runtime = Arc::new(tokio::runtime::Runtime::new().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to create async runtime: {}",
                e
            ))
        })?);

        let client = btlightning::LightningClient::new(wallet_hotkey);

        Ok(Self {
            client: Mutex::new(client),
            runtime,
        })
    }

    pub fn set_validator_keypair(&self, keypair_seed: [u8; 32]) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        runtime.block_on(async {
            let mut client = self.client.lock().await;
            client.set_signer(Box::new(btlightning::Sr25519Signer::from_seed(keypair_seed)));
            Ok(())
        })
    }

    pub fn set_python_signer(&self, signer_callback: PyObject) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        runtime.block_on(async {
            let mut client = self.client.lock().await;
            client.set_signer(Box::new(PythonSigner::new(signer_callback)));
            Ok(())
        })
    }

    pub fn initialize_connections(&self, miners: Vec<PyObject>) -> PyResult<()> {
        pyo3::Python::with_gil(|py| {
            let mut quic_miners = Vec::new();

            for miner_obj in miners {
                quic_miners.push(extract_quic_axon_info(py, &miner_obj)?);
            }

            let runtime = Arc::clone(&self.runtime);
            runtime.block_on(async {
                let mut client = self.client.lock().await;
                client
                    .initialize_connections(quic_miners)
                    .await
                    .map_err(to_pyerr)
            })
        })
    }

    pub fn query_axon(&self, axon_data: PyObject, request_data: PyObject) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let request_dict = request_data.extract::<HashMap<String, PyObject>>(py)?;

            let axon_info = extract_quic_axon_info(py, &axon_data)?;

            let synapse_type = request_dict
                .get("synapse_type")
                .ok_or_else(|| {
                    PyErr::new::<pyo3::exceptions::PyKeyError, _>("Missing 'synapse_type' field")
                })?
                .extract::<String>(py)?;

            let mut data = HashMap::new();
            if let Some(data_obj) = request_dict.get("data") {
                let data_dict = data_obj.extract::<HashMap<String, PyObject>>(py)?;
                let json_module = py.import("json")?;
                for (key, value) in data_dict {
                    let json_str = json_module
                        .call_method1("dumps", (value,))?
                        .extract::<String>()?;
                    let json_value: serde_json::Value =
                        serde_json::from_str(&json_str).map_err(|e| {
                            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                                "Failed to parse JSON from Python: {}",
                                e
                            ))
                        })?;
                    data.insert(key, json_value);
                }
            }

            let request = btlightning::QuicRequest::new(synapse_type, data);

            let runtime = Arc::clone(&self.runtime);
            let response = runtime.block_on(async {
                let client = self.client.lock().await;
                client.query_axon(axon_info, request).await.map_err(to_pyerr)
            })?;

            let result_dict = pyo3::types::PyDict::new(py);
            result_dict.set_item("success", response.success)?;
            result_dict.set_item("latency_ms", response.latency_ms)?;

            for (key, value) in response.data {
                let py_value = match value {
                    serde_json::Value::String(s) => s.into_py(py),
                    serde_json::Value::Number(n) => {
                        if let Some(i) = n.as_i64() {
                            i.into_py(py)
                        } else if let Some(f) = n.as_f64() {
                            f.into_py(py)
                        } else {
                            n.to_string().into_py(py)
                        }
                    }
                    serde_json::Value::Bool(b) => b.into_py(py),
                    _ => serde_json::to_string(&value)
                        .unwrap_or_default()
                        .into_py(py),
                };
                result_dict.set_item(key, py_value)?;
            }

            Ok(result_dict.into())
        })
    }

    pub fn update_miner_registry(&self, miners: Vec<PyObject>) -> PyResult<()> {
        pyo3::Python::with_gil(|py| {
            let mut quic_miners = Vec::new();

            for miner_obj in miners {
                quic_miners.push(extract_quic_axon_info(py, &miner_obj)?);
            }

            let runtime = Arc::clone(&self.runtime);
            runtime.block_on(async {
                let mut client = self.client.lock().await;
                client
                    .update_miner_registry(quic_miners)
                    .await
                    .map_err(to_pyerr)
            })
        })
    }

    pub fn get_connection_stats(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let runtime = Arc::clone(&self.runtime);
            let stats = runtime.block_on(async {
                let client = self.client.lock().await;
                client.get_connection_stats().await.map_err(to_pyerr)
            })?;

            let result_dict = pyo3::types::PyDict::new(py);
            for (key, value) in stats {
                result_dict.set_item(key, value)?;
            }

            Ok(result_dict.into())
        })
    }

    pub fn close_all_connections(&self) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        runtime.block_on(async {
            let client = self.client.lock().await;
            client.close_all_connections().await.map_err(to_pyerr)
        })
    }
}

#[pyclass]
pub struct RustLightningServer {
    server: Mutex<btlightning::LightningServer>,
    runtime: Arc<tokio::runtime::Runtime>,
}

#[pymethods]
impl RustLightningServer {
    #[new]
    pub fn new(miner_hotkey: String, host: String, port: u16) -> PyResult<Self> {
        let runtime = Arc::new(tokio::runtime::Runtime::new().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to create async runtime: {}",
                e
            ))
        })?);

        let server = btlightning::LightningServer::new(miner_hotkey, host, port);

        Ok(Self {
            server: Mutex::new(server),
            runtime,
        })
    }

    pub fn register_synapse_handler(
        &self,
        synapse_type: String,
        handler: PyObject,
    ) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        runtime.block_on(async {
            let server = self.server.lock().await;
            server
                .register_synapse_handler(
                    synapse_type,
                    Arc::new(PythonSynapseHandler::new(handler)),
                )
                .await
                .map_err(to_pyerr)
        })
    }

    pub fn start(&self) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        runtime.block_on(async {
            let mut server = self.server.lock().await;
            server.start().await.map_err(to_pyerr)
        })
    }

    pub fn serve_forever(&self) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        runtime.block_on(async {
            let mut server = self.server.lock().await;
            server.serve_forever().await.map_err(to_pyerr)
        })
    }

    pub fn get_connection_stats(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let runtime = Arc::clone(&self.runtime);
            let stats = runtime.block_on(async {
                let server = self.server.lock().await;
                server.get_connection_stats().await.map_err(to_pyerr)
            })?;

            let result_dict = pyo3::types::PyDict::new(py);
            for (key, value) in stats {
                result_dict.set_item(key, value)?;
            }

            Ok(result_dict.into())
        })
    }

    pub fn cleanup_stale_connections(&self, max_idle_seconds: u64) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        runtime.block_on(async {
            let server = self.server.lock().await;
            server
                .cleanup_stale_connections(max_idle_seconds)
                .await
                .map_err(to_pyerr)
        })
    }

    pub fn stop(&self) -> PyResult<()> {
        let runtime = Arc::clone(&self.runtime);
        runtime.block_on(async {
            let server = self.server.lock().await;
            server.stop().await.map_err(to_pyerr)
        })
    }
}

fn extract_quic_axon_info(
    py: Python,
    miner_obj: &PyObject,
) -> PyResult<btlightning::QuicAxonInfo> {
    let miner_dict = miner_obj.extract::<HashMap<String, PyObject>>(py)?;

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
fn _native(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<RustLightning>()?;
    m.add_class::<RustLightningServer>()?;
    m.add_class::<PyQuicAxonInfo>()?;
    Ok(())
}
