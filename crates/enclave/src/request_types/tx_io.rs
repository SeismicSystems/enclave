use serde::{Deserialize, Serialize};

use crate::request_types::nonce::Nonce;

/// Struct representing the encryption request.
///
/// # Fields
/// * `key` - The ephemeral secp256k1 public key.
/// * `data` - The data to be encrypted, represented as a `Vec<u8>`.
/// * `nonce` - A 64-bit unsigned integer used as a nonce in the encryption process.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptionRequest {
    pub key: secp256k1::PublicKey,
    pub data: Vec<u8>,
    pub nonce: Nonce,
}

/// Struct representing the encryption response.
///
/// # Fields
/// * `encrypted_data` - The encrypted data, represented as a `Vec<u8>`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptionResponse {
    pub encrypted_data: Vec<u8>,
}

/// Struct representing the decryption request.
///
/// # Fields
/// * `key` - The ephemeral secp256k1 public key.
/// * `data` - The encrypted data to be decrypted, represented as a `Vec<u8>`.
/// * `nonce` - A 64-bit unsigned integer used as a nonce in the decryption process.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DecryptionRequest {
    pub key: secp256k1::PublicKey,
    pub data: Vec<u8>,
    pub nonce: Nonce,
}

/// Struct representing the decryption response.
///
/// # Fields
/// * `decrypted_data` - The decrypted data, represented as a `Vec<u8>`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DecryptionResponse {
    pub decrypted_data: Vec<u8>,
}

pub enum MockEnclaveResponse {
    Success(Vec<u8>),
    Error(anyhow::Error),
}

impl MockEnclaveResponse {
    pub fn unwrap(self) -> Vec<u8> {
        match self {
            MockEnclaveResponse::Success(data) => data,
            MockEnclaveResponse::Error(e) => panic!("{:?}", e),
        }
    }
}
