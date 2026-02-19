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

#[cfg(feature = "btwallet")]
pub struct BtWalletSigner {
    keypair: bittensor_wallet::Keypair,
}

#[cfg(feature = "btwallet")]
impl BtWalletSigner {
    pub fn new(keypair: bittensor_wallet::Keypair) -> Self {
        Self { keypair }
    }

    pub fn from_wallet(name: &str, path: &str, hotkey_name: &str) -> Result<Self> {
        let wallet = bittensor_wallet::Wallet::new(
            Some(name.to_string()),
            Some(path.to_string()),
            Some(hotkey_name.to_string()),
            None,
        );
        let keypair = wallet
            .get_hotkey(Some(hotkey_name.to_string()))
            .map_err(|e| {
                LightningError::Config(format!("failed to load hotkey from wallet: {}", e))
            })?;
        Ok(Self { keypair })
    }
}

#[cfg(feature = "btwallet")]
impl Signer for BtWalletSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.keypair
            .sign(message.to_vec())
            .map_err(LightningError::Signing)
    }
}
