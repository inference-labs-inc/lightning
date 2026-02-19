use btlightning::{LightningError, Result, Signer};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

pub struct PythonSigner {
    callback: Py<PyAny>,
}

impl PythonSigner {
    pub fn new(callback: Py<PyAny>) -> Self {
        Self { callback }
    }
}

impl Signer for PythonSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        Python::attach(|py| {
            let py_bytes = PyBytes::new(py, message);
            let result = self.callback.call1(py, (py_bytes,)).map_err(|e| {
                LightningError::Signing(format!("Python signer call failed: {}", e))
            })?;
            let signature_bytes: Vec<u8> = result.extract(py).map_err(|e| {
                LightningError::Signing(format!("Failed to extract signature bytes: {}", e))
            })?;
            Ok(signature_bytes)
        })
    }
}
