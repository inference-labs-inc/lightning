use btlightning::{LightningError, Result, Signer, ValidatorPermitResolver};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::collections::HashSet;

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

pub struct PythonPermitResolver {
    callback: Py<PyAny>,
}

impl PythonPermitResolver {
    pub fn new(callback: Py<PyAny>) -> Self {
        Self { callback }
    }
}

impl ValidatorPermitResolver for PythonPermitResolver {
    fn resolve_permitted_validators(&self) -> Result<HashSet<String>> {
        Python::attach(|py| {
            let result = self.callback.call0(py).map_err(|e| {
                LightningError::Handler(format!("Python permit resolver call failed: {}", e))
            })?;
            let validators: HashSet<String> = result.extract(py).map_err(|e| {
                LightningError::Handler(format!(
                    "Failed to extract validator set from Python: {}",
                    e
                ))
            })?;
            Ok(validators)
        })
    }
}
