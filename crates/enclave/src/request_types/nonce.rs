use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::digest::{consts::U12, generic_array::GenericArray};

pub const AESGCM_NONCE_SIZE: usize = 12; // Size of AES-GCM nonce in bytes

/// The intermediate type to represent a nonce in the enclave
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Nonce(pub [u8; AESGCM_NONCE_SIZE]);

impl Nonce {
    pub fn new_rand() -> Self {
        let mut rng = rand::rng();
        // Generate a random U96 value
        let mut bytes = [0u8; 12]; // 96 bits = 12 bytes
        rng.fill_bytes(&mut bytes);
        Nonce(bytes)
    }
}

impl From<Nonce> for aes_gcm::Nonce<U12> {
    fn from(nonce: Nonce) -> Self {
        GenericArray::clone_from_slice(&nonce.0)
    }
}

impl From<[u8; AESGCM_NONCE_SIZE]> for Nonce {
    fn from(bytes: [u8; AESGCM_NONCE_SIZE]) -> Self {
        Nonce(bytes)
    }
}
