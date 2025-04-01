use zeroize::{Zeroize, ZeroizeOnDrop};

mod builder;
mod manager;

// re-export important types
pub use manager::KeyManager;
pub use builder::KeyManagerBuilder;


/// A secure wrapper around a 32-byte master secret key.
///
/// Implements [`Zeroize`] and [`ZeroizeOnDrop`] to ensure the memory is cleared
/// when the value is dropped or explicitly zeroized.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct Secret(pub [u8; 32]);

impl Secret {
    /// Creates a new `Secret` from a 32-byte array.
    pub fn new(data: [u8; 32]) -> Self {
        Secret(data)
    }

    /// Returns a `Secret` filled with zeros.
    pub fn empty() -> Self {
        Secret([0u8; 32])
    }

    /// Constructs a `Secret` from a `Vec<u8>`.
    ///
    /// Returns an error if the vector is not exactly 32 bytes.
    pub fn from_vec(vec: Vec<u8>) -> Result<Self, anyhow::Error> {
        if vec.len() != 32 {
            anyhow::bail!("Invalid secret size: expected 32 bytes, got {}", vec.len());
        }
        let mut data = [0u8; 32];
        data.copy_from_slice(&vec);
        Ok(Secret(data))
    }
}

impl AsRef<[u8]> for Secret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Represents a derived key used for specific cryptographic purposes.
///
/// Typically created via HKDF derivation from a master [`Secret`].
#[derive(Debug, Clone)]
struct Key {
    pub bytes: Vec<u8>,
}

impl Key {
    /// Creates a new `Key` from the given byte vector.
    ///
    /// This is primarily used internally by the key manager when deriving keys.
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

/// Trait for providing access to derived keys used in networking and other runtime logic.
///
/// Used to abstract over how keys are retrieved (e.g., real or mocked key managers).
pub trait NetworkKeyProvider: Sync {
    /// Retrieves the secp256k1 secret key used for transaction I/O.
    fn get_tx_io_sk(&self) -> secp256k1::SecretKey;

    /// Retrieves the secp256k1 public key corresponding to the transaction I/O secret key.
    fn get_tx_io_pk(&self) -> secp256k1::PublicKey;

    /// Retrieves the Schnorrkel keypair used for generating randomness.
    fn get_rng_keypair(&self) -> schnorrkel::keys::Keypair;

    /// Retrieves the AES-256-GCM encryption key used for snapshot encryption.
    fn get_snapshot_key(&self) -> aes_gcm::Key<aes_gcm::Aes256Gcm>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_from_vec_valid() {
        let vec_32 = vec![1u8; 32];
        let secret = Secret::from_vec(vec_32).unwrap();
        assert_eq!(secret.as_ref().len(), 32);
    }

    #[test]
    fn test_secret_from_vec_invalid_length() {
        let vec_16 = vec![1u8; 16];
        let res = Secret::from_vec(vec_16);

        assert!(res.is_err(), "Expected error for invalid secret size");

        if let Err(e) = res {
            let msg = e.to_string();
            assert!(
                msg.contains("Invalid secret size"),
                "Unexpected error message: {}",
                msg
            );
        }
    }
}
