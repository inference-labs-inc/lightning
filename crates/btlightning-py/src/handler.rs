use btlightning::{LightningError, Result, StreamingSynapseHandler, SynapseHandler};
use pyo3::prelude::*;
use std::collections::HashMap;
use std::sync::Mutex;

pub struct PythonSynapseHandler {
    callback: Mutex<PyObject>,
}

impl PythonSynapseHandler {
    pub fn new(callback: PyObject) -> Self {
        Self {
            callback: Mutex::new(callback),
        }
    }
}

impl SynapseHandler for PythonSynapseHandler {
    fn handle(
        &self,
        _synapse_type: &str,
        data: HashMap<String, rmpv::Value>,
    ) -> Result<HashMap<String, rmpv::Value>> {
        let callback = self
            .callback
            .lock()
            .map_err(|e| LightningError::Handler(format!("lock poisoned: {}", e)))?;
        Python::with_gil(|py| {
            let py_dict = pyo3::types::PyDict::new(py);

            for (key, value) in &data {
                let py_value = msgpack_value_to_py(py, value);
                py_dict
                    .set_item(key, py_value)
                    .map_err(|e| LightningError::Handler(e.to_string()))?;
            }

            let result = callback
                .call1(py, (py_dict,))
                .map_err(|e| LightningError::Handler(format!("Python handler error: {}", e)))?;

            let result_dict: &pyo3::types::PyDict = result
                .extract(py)
                .map_err(|e| LightningError::Handler(e.to_string()))?;

            let mut response_data = HashMap::new();
            for (key, value) in result_dict.iter() {
                let key_str: String = key
                    .extract()
                    .map_err(|e| LightningError::Handler(e.to_string()))?;
                let value_msgpack = py_to_msgpack_value(value)
                    .map_err(|e| LightningError::Handler(e.to_string()))?;
                response_data.insert(key_str, value_msgpack);
            }

            Ok(response_data)
        })
    }
}

pub struct PythonStreamingSynapseHandler {
    callback: Mutex<PyObject>,
}

impl PythonStreamingSynapseHandler {
    pub fn new(callback: PyObject) -> Self {
        Self {
            callback: Mutex::new(callback),
        }
    }
}

#[async_trait::async_trait]
impl StreamingSynapseHandler for PythonStreamingSynapseHandler {
    async fn handle(
        &self,
        _synapse_type: &str,
        data: HashMap<String, rmpv::Value>,
        sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> Result<()> {
        let callback = self
            .callback
            .lock()
            .map_err(|e| LightningError::Handler(format!("lock poisoned: {}", e)))?
            .clone();

        tokio::task::spawn_blocking(move || {
            Python::with_gil(|py| {
                let py_dict = pyo3::types::PyDict::new(py);
                for (key, value) in &data {
                    let py_value = msgpack_value_to_py(py, value);
                    py_dict
                        .set_item(key, py_value)
                        .map_err(|e| LightningError::Handler(e.to_string()))?;
                }

                let py_iter = callback
                    .call1(py, (py_dict,))
                    .map_err(|e| LightningError::Handler(format!("Python handler error: {}", e)))?;

                let iter = py_iter.as_ref(py).iter().map_err(|e| {
                    LightningError::Handler(format!(
                        "Python handler must return an iterable: {}",
                        e
                    ))
                })?;

                for item in iter {
                    let item = item.map_err(|e| {
                        LightningError::Handler(format!("Python iterator error: {}", e))
                    })?;
                    let bytes: Vec<u8> = item.extract().map_err(|e| {
                        LightningError::Handler(format!(
                            "Streaming handler must yield bytes: {}",
                            e
                        ))
                    })?;
                    sender
                        .blocking_send(bytes)
                        .map_err(|_| LightningError::Stream("client disconnected".to_string()))?;
                }

                Ok(())
            })
        })
        .await
        .map_err(|e| LightningError::Handler(format!("handler panicked: {}", e)))?
    }
}

pub fn msgpack_value_to_py(py: Python, value: &rmpv::Value) -> PyObject {
    match value {
        rmpv::Value::Nil => py.None(),
        rmpv::Value::Boolean(b) => b.to_object(py),
        rmpv::Value::Integer(i) => {
            if let Some(v) = i.as_i64() {
                v.to_object(py)
            } else if let Some(v) = i.as_u64() {
                v.to_object(py)
            } else {
                py.None()
            }
        }
        rmpv::Value::F32(f) => f.to_object(py),
        rmpv::Value::F64(f) => f.to_object(py),
        rmpv::Value::String(s) => match s.as_str() {
            Some(st) => st.to_object(py),
            None => s.as_bytes().to_object(py),
        },
        rmpv::Value::Binary(b) => pyo3::types::PyBytes::new(py, b).to_object(py),
        rmpv::Value::Array(arr) => {
            let py_list = pyo3::types::PyList::empty(py);
            for item in arr {
                let _ = py_list.append(msgpack_value_to_py(py, item));
            }
            py_list.to_object(py)
        }
        rmpv::Value::Map(entries) => {
            let py_dict = pyo3::types::PyDict::new(py);
            for (k, v) in entries {
                let py_key = msgpack_value_to_py(py, k);
                let py_val = msgpack_value_to_py(py, v);
                let _ = py_dict.set_item(py_key, py_val);
            }
            py_dict.to_object(py)
        }
        rmpv::Value::Ext(_type_id, data) => pyo3::types::PyBytes::new(py, data).to_object(py),
    }
}

pub fn py_to_msgpack_value(value: &PyAny) -> PyResult<rmpv::Value> {
    if value.is_none() {
        Ok(rmpv::Value::Nil)
    } else if let Ok(b) = value.extract::<bool>() {
        Ok(rmpv::Value::Boolean(b))
    } else if let Ok(i) = value.extract::<i64>() {
        Ok(rmpv::Value::Integer(rmpv::Integer::from(i)))
    } else if let Ok(f) = value.extract::<f64>() {
        Ok(rmpv::Value::F64(f))
    } else if let Ok(s) = value.extract::<String>() {
        Ok(rmpv::Value::String(rmpv::Utf8String::from(s.as_str())))
    } else if let Ok(b) = value.extract::<Vec<u8>>() {
        Ok(rmpv::Value::Binary(b))
    } else if let Ok(list) = value.downcast::<pyo3::types::PyList>() {
        let mut arr = Vec::new();
        for item in list.iter() {
            arr.push(py_to_msgpack_value(item)?);
        }
        Ok(rmpv::Value::Array(arr))
    } else if let Ok(dict) = value.downcast::<pyo3::types::PyDict>() {
        let mut entries = Vec::new();
        for (k, v) in dict.iter() {
            entries.push((py_to_msgpack_value(k)?, py_to_msgpack_value(v)?));
        }
        Ok(rmpv::Value::Map(entries))
    } else {
        let s: String = value.str()?.extract()?;
        Ok(rmpv::Value::String(rmpv::Utf8String::from(s.as_str())))
    }
}
