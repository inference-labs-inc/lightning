use btlightning::{LightningError, Result, StreamingSynapseHandler, SynapseHandler};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::collections::HashMap;
use std::sync::Mutex;

pub struct PythonSynapseHandler {
    callback: Mutex<Py<PyAny>>,
}

impl PythonSynapseHandler {
    pub fn new(callback: Py<PyAny>) -> Self {
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
        Python::attach(|py| {
            let py_dict = PyDict::new(py);

            for (key, value) in &data {
                let py_value = msgpack_value_to_py(py, value)
                    .map_err(|e| LightningError::Handler(e.to_string()))?;
                py_dict
                    .set_item(key, py_value)
                    .map_err(|e| LightningError::Handler(e.to_string()))?;
            }

            let result = callback
                .call1(py, (&py_dict,))
                .map_err(|e| LightningError::Handler(format!("Python handler error: {}", e)))?;

            let result_bound = result.bind(py);
            let result_dict = result_bound
                .downcast::<PyDict>()
                .map_err(|e| LightningError::Handler(e.to_string()))?;

            let mut response_data = HashMap::new();
            for (key, value) in result_dict.iter() {
                let key_str: String = key
                    .extract()
                    .map_err(|e| LightningError::Handler(e.to_string()))?;
                let value_msgpack = py_to_msgpack_value(&value)
                    .map_err(|e| LightningError::Handler(e.to_string()))?;
                response_data.insert(key_str, value_msgpack);
            }

            Ok(response_data)
        })
    }
}

pub struct PythonStreamingSynapseHandler {
    callback: Mutex<Py<PyAny>>,
}

impl PythonStreamingSynapseHandler {
    pub fn new(callback: Py<PyAny>) -> Self {
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
        let callback = Python::attach(|py| {
            let guard = self
                .callback
                .lock()
                .map_err(|e| LightningError::Handler(format!("lock poisoned: {}", e)))?;
            Ok::<_, LightningError>(guard.clone_ref(py))
        })?;

        tokio::task::spawn_blocking(move || {
            Python::attach(|py| {
                let py_dict = PyDict::new(py);
                for (key, value) in &data {
                    let py_value = msgpack_value_to_py(py, value)
                        .map_err(|e| LightningError::Handler(e.to_string()))?;
                    py_dict
                        .set_item(key, py_value)
                        .map_err(|e| LightningError::Handler(e.to_string()))?;
                }

                let py_iter = callback
                    .call1(py, (&py_dict,))
                    .map_err(|e| LightningError::Handler(format!("Python handler error: {}", e)))?;

                let iter = py_iter.bind(py).try_iter().map_err(|e| {
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

pub fn msgpack_value_to_py(py: Python, value: &rmpv::Value) -> PyResult<Py<PyAny>> {
    match value {
        rmpv::Value::Nil => Ok(py.None()),
        rmpv::Value::Boolean(b) => Ok(b.into_pyobject(py)?.to_owned().into_any().unbind()),
        rmpv::Value::Integer(i) => {
            if let Some(v) = i.as_i64() {
                Ok(v.into_pyobject(py)?.into_any().unbind())
            } else if let Some(v) = i.as_u64() {
                Ok(v.into_pyobject(py)?.into_any().unbind())
            } else {
                Ok(py.None())
            }
        }
        rmpv::Value::F32(f) => Ok(f.into_pyobject(py)?.into_any().unbind()),
        rmpv::Value::F64(f) => Ok(f.into_pyobject(py)?.into_any().unbind()),
        rmpv::Value::String(s) => match s.as_str() {
            Some(st) => Ok(st.into_pyobject(py)?.into_any().unbind()),
            None => Ok(s.as_bytes().into_pyobject(py)?.into_any().unbind()),
        },
        rmpv::Value::Binary(b) => Ok(PyBytes::new(py, b).into_any().unbind()),
        rmpv::Value::Array(arr) => {
            let py_list = PyList::empty(py);
            for item in arr {
                py_list.append(msgpack_value_to_py(py, item)?)?;
            }
            Ok(py_list.into_any().unbind())
        }
        rmpv::Value::Map(entries) => {
            let py_dict = PyDict::new(py);
            for (k, v) in entries {
                let py_key = msgpack_value_to_py(py, k)?;
                let py_val = msgpack_value_to_py(py, v)?;
                py_dict.set_item(py_key, py_val)?;
            }
            Ok(py_dict.into_any().unbind())
        }
        rmpv::Value::Ext(_type_id, data) => Ok(PyBytes::new(py, data).into_any().unbind()),
    }
}

pub fn py_to_msgpack_value(value: &Bound<'_, pyo3::PyAny>) -> PyResult<rmpv::Value> {
    if value.is_none() {
        Ok(rmpv::Value::Nil)
    } else if let Ok(b) = value.extract::<bool>() {
        Ok(rmpv::Value::Boolean(b))
    } else if let Ok(i) = value.extract::<i64>() {
        Ok(rmpv::Value::Integer(rmpv::Integer::from(i)))
    } else if let Ok(u) = value.extract::<u64>() {
        Ok(rmpv::Value::Integer(rmpv::Integer::from(u)))
    } else if let Ok(f) = value.extract::<f64>() {
        Ok(rmpv::Value::F64(f))
    } else if let Ok(s) = value.extract::<String>() {
        Ok(rmpv::Value::String(rmpv::Utf8String::from(s.as_str())))
    } else if let Ok(list) = value.downcast::<PyList>() {
        let mut arr = Vec::new();
        for item in list.iter() {
            arr.push(py_to_msgpack_value(&item)?);
        }
        Ok(rmpv::Value::Array(arr))
    } else if let Ok(dict) = value.downcast::<PyDict>() {
        let mut entries = Vec::new();
        for (k, v) in dict.iter() {
            entries.push((py_to_msgpack_value(&k)?, py_to_msgpack_value(&v)?));
        }
        Ok(rmpv::Value::Map(entries))
    } else if let Ok(b) = value.extract::<Vec<u8>>() {
        Ok(rmpv::Value::Binary(b))
    } else {
        let s: String = value.str()?.extract()?;
        Ok(rmpv::Value::String(rmpv::Utf8String::from(s.as_str())))
    }
}
