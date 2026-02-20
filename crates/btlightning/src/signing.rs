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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sr25519_signer_produces_valid_signature() {
        let seed = [1u8; 32];
        let signer = Sr25519Signer::from_seed(seed);
        let message = b"test message";
        let sig_bytes = signer.sign(message).unwrap();
        assert_eq!(sig_bytes.len(), 64);
        let public = sr25519::Pair::from_seed(&seed).public();
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);
        let signature = sr25519::Signature::from_raw(sig_array);
        assert!(sr25519::Pair::verify(&signature, message, &public));
    }

    #[test]
    fn sr25519_signer_same_seed_both_valid() {
        let seed = [42u8; 32];
        let message = b"both valid check";
        let public = sr25519::Pair::from_seed(&seed).public();
        let sig1 = Sr25519Signer::from_seed(seed).sign(message).unwrap();
        let sig2 = Sr25519Signer::from_seed(seed).sign(message).unwrap();
        for sig_bytes in [&sig1, &sig2] {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(sig_bytes);
            assert!(sr25519::Pair::verify(
                &sr25519::Signature::from_raw(arr),
                message,
                &public
            ));
        }
    }

    #[test]
    fn sr25519_signer_different_seeds_differ() {
        let message = b"same message";
        let sig1 = Sr25519Signer::from_seed([1u8; 32]).sign(message).unwrap();
        let sig2 = Sr25519Signer::from_seed([2u8; 32]).sign(message).unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn callback_signer_invokes_callback() {
        let signer = CallbackSigner::new(|msg: &[u8]| Ok(msg.to_vec()));
        let result = signer.sign(b"hello").unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn callback_signer_propagates_error() {
        let signer = CallbackSigner::new(|_: &[u8]| Err(LightningError::Signing("boom".into())));
        let err = signer.sign(b"x").unwrap_err();
        assert!(err.to_string().contains("boom"));
    }

    #[test]
    fn callback_signer_wraps_as_signing_variant() {
        let signer =
            CallbackSigner::new(|_: &[u8]| Err(LightningError::Transport("network down".into())));
        let err = signer.sign(b"x").unwrap_err();
        assert!(
            matches!(err, LightningError::Signing(_)),
            "expected Signing variant, got: {:?}",
            err
        );
        assert!(err.to_string().contains("network down"));
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
