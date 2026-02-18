use btlightning::{LightningError, Result, Signer};
use pyo3::prelude::*;
use std::sync::Mutex;

pub struct PythonSigner {
    callback: Mutex<PyObject>,
}

impl PythonSigner {
    pub fn new(callback: PyObject) -> Self {
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
        Python::with_gil(|py| {
            let message_str = std::str::from_utf8(message)
                .map_err(|e| LightningError::Signing(e.to_string()))?;
            let result = callback.call1(py, (message_str,)).map_err(|e| {
                LightningError::Signing(format!("Python signer call failed: {}", e))
            })?;
            let signature_bytes: Vec<u8> = result.extract(py).map_err(|e| {
                LightningError::Signing(format!("Failed to extract signature bytes: {}", e))
            })?;
            Ok(signature_bytes)
        })
    }
}
