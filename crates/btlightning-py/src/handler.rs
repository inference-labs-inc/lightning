use btlightning::{LightningError, Result, SynapseHandler};
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
        data: HashMap<String, serde_json::Value>,
    ) -> Result<HashMap<String, serde_json::Value>> {
        let callback = self
            .callback
            .lock()
            .map_err(|e| LightningError::Handler(format!("lock poisoned: {}", e)))?;
        Python::with_gil(|py| {
            let py_dict = pyo3::types::PyDict::new(py);

            for (key, value) in &data {
                let py_value = json_value_to_py(py, value);
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
                let value_json =
                    py_to_json_value(value).map_err(|e| LightningError::Handler(e.to_string()))?;
                response_data.insert(key_str, value_json);
            }

            Ok(response_data)
        })
    }
}

fn json_value_to_py(py: Python, value: &serde_json::Value) -> PyObject {
    match value {
        serde_json::Value::String(s) => s.to_object(py),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_object(py)
            } else if let Some(f) = n.as_f64() {
                f.to_object(py)
            } else {
                n.to_string().to_object(py)
            }
        }
        serde_json::Value::Bool(b) => b.to_object(py),
        serde_json::Value::Array(arr) => {
            let py_list = pyo3::types::PyList::empty(py);
            for item in arr {
                let _ = py_list.append(json_value_to_py(py, item));
            }
            py_list.to_object(py)
        }
        serde_json::Value::Object(obj) => {
            let py_dict = pyo3::types::PyDict::new(py);
            for (k, v) in obj {
                let _ = py_dict.set_item(k, json_value_to_py(py, v));
            }
            py_dict.to_object(py)
        }
        serde_json::Value::Null => py.None(),
    }
}

fn py_to_json_value(value: &PyAny) -> PyResult<serde_json::Value> {
    if let Ok(s) = value.extract::<String>() {
        Ok(serde_json::Value::String(s))
    } else if let Ok(b) = value.extract::<bool>() {
        Ok(serde_json::Value::Bool(b))
    } else if let Ok(i) = value.extract::<i64>() {
        Ok(serde_json::Value::Number(serde_json::Number::from(i)))
    } else if let Ok(f) = value.extract::<f64>() {
        Ok(serde_json::Number::from_f64(f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null))
    } else {
        let s: String = value.str()?.extract()?;
        Ok(serde_json::Value::String(s))
    }
}
