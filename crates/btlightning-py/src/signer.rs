use btlightning::{LightningError, Result, Signer};
use pyo3::prelude::*;

pub struct PythonSigner {
    callback: PyObject,
}

unsafe impl Sync for PythonSigner {}

impl PythonSigner {
    pub fn new(callback: PyObject) -> Self {
        Self { callback }
    }
}

impl Signer for PythonSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        Python::with_gil(|py| {
            let message_str = std::str::from_utf8(message)
                .map_err(|e| LightningError::Signing(e.to_string()))?;
            let result = self
                .callback
                .call1(py, (message_str,))
                .map_err(|e| {
                    LightningError::Signing(format!("Python signer call failed: {}", e))
                })?;
            let signature_bytes: Vec<u8> = result.extract(py).map_err(|e| {
                LightningError::Signing(format!("Failed to extract signature bytes: {}", e))
            })?;
            Ok(signature_bytes)
        })
    }
}
