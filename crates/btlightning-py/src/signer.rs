use btlightning::{LightningError, Result, Signer};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::sync::Mutex;

pub struct PythonSigner {
    callback: Mutex<Py<PyAny>>,
}

impl PythonSigner {
    pub fn new(callback: Py<PyAny>) -> Self {
        Self {
            callback: Mutex::new(callback),
        }
    }
}

impl Signer for PythonSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let callback = self
            .callback
            .lock()
            .map_err(|e| LightningError::Signing(format!("lock poisoned: {}", e)))?;
        Python::attach(|py| {
            let py_bytes = PyBytes::new(py, message);
            let result = callback.call1(py, (py_bytes,)).map_err(|e| {
                LightningError::Signing(format!("Python signer call failed: {}", e))
            })?;
            let signature_bytes: Vec<u8> = result.extract(py).map_err(|e| {
                LightningError::Signing(format!("Failed to extract signature bytes: {}", e))
            })?;
            Ok(signature_bytes)
        })
    }
}
