pub mod builder;
pub mod key_manager;

use anyhow::{anyhow, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret(pub [u8; 32]);

impl Secret {
    pub fn new(data: [u8; 32]) -> Self {
        Secret(data)
    }

    pub fn empty() -> Self {
        Secret([0u8; 32])
    }

    pub fn from_vec(vec: Vec<u8>) -> Result<Self> {
        if vec.len() != 32 {
            return Err(anyhow!(
                "Invalid secret size: expected 32 bytes, got {}",
                vec.len()
            ));
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

#[derive(Debug, Clone)]
pub struct Key {
    pub bytes: Vec<u8>,
}

impl Key {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

pub trait NetworkKeyProvider {
    /// Loads a secp256k1 private key
    fn get_secp256k1_sk(&self) -> secp256k1::SecretKey;

    /// Loads a secp256k1 public key
    fn get_secp256k1_pk(&self) -> secp256k1::PublicKey;

    /// Loads a Schnorrkel keypair
    fn get_schnorrkel_keypair(&self) -> schnorrkel::keys::Keypair;

    /// Generates an AES-GCM encryption key for snapshot encryption.
    fn get_snapshot_key(&self) -> aes_gcm::Key<aes_gcm::Aes256Gcm>;
}
