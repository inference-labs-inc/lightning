use pyo3::prelude::*;
use std::collections::HashMap;

use crate::handler::{msgpack_value_to_py, py_to_msgpack_value};

pub(crate) fn extract_quic_request(
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

pub(crate) fn extract_quic_axon_info(
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
    Ok(btlightning::QuicAxonInfo::new(hotkey, ip, port, protocol))
}

pub(crate) fn response_to_py(
    py: Python<'_>,
    response: &btlightning::QuicResponse,
) -> PyResult<Py<PyAny>> {
    let result_dict = pyo3::types::PyDict::new(py);
    let data_dict = pyo3::types::PyDict::new(py);
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

pub(crate) fn stats_to_py(py: Python<'_>, stats: HashMap<String, String>) -> PyResult<Py<PyAny>> {
    let result_dict = pyo3::types::PyDict::new(py);
    for (key, value) in stats {
        result_dict.set_item(key, value)?;
    }
    Ok(result_dict.into_any().unbind())
}
