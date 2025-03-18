use rand::RngCore;
use serde::{Deserialize, Serialize};

pub const AESGCM_NONCE_SIZE: usize = 12; // Size of AES-GCM nonce in bytes

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Nonce([u8; AESGCM_NONCE_SIZE]);

impl Nonce {
    pub fn new_rand() -> Self {
        let mut rng = rand::rng();
        // Generate a random U96 value
        let mut bytes = [0u8; 12]; // 96 bits = 12 bytes
        rng.fill_bytes(&mut bytes);
        Nonce(bytes)
    }
}
