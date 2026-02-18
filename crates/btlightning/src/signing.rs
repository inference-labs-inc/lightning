use crate::error::{LightningError, Result};
use sp_core::{sr25519, Pair};

pub trait Signer: Send + Sync {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
}

pub struct Sr25519Signer {
    pair: sr25519::Pair,
}

impl Sr25519Signer {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            pair: sr25519::Pair::from_seed(&seed),
        }
    }
}

impl Signer for Sr25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signature = self.pair.sign(message);
        Ok(signature.0.to_vec())
    }
}

pub struct CallbackSigner<F: Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync> {
    callback: F,
}

impl<F: Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync> CallbackSigner<F> {
    pub fn new(callback: F) -> Self {
        Self { callback }
    }
}

impl<F: Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync> Signer for CallbackSigner<F> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        (self.callback)(message).map_err(|e| LightningError::Signing(e.to_string()))
    }
}
