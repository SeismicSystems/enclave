use serde::{Deserialize, Serialize};

use crate::request_types::nonce::Nonce;

/// Struct representing the IO encryption request.
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

/// Struct representing the IO encryption response.
///
/// # Fields
/// * `encrypted_data` - The encrypted data, represented as a `Vec<u8>`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum EncryptionResponse {
    Success(Vec<u8>),
    Error(String),
}

/// Struct representing the IO decryption request.
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

/// Struct representing the IO decryption response.
///
/// # Fields
/// * `decrypted_data` - The decrypted data, represented as a `Vec<u8>`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum DecryptionResponse {
    Success(Vec<u8>),
    Error(String),
}

impl EncryptionResponse {
    pub fn unwrap(self) -> Vec<u8> {
        match self {
            EncryptionResponse::Success(data) => data,
            EncryptionResponse::Error(e) => panic!("{}", e),
        }
    }
}

impl DecryptionResponse {
    pub fn unwrap(self) -> Vec<u8> {
        match self {
            DecryptionResponse::Success(data) => data,
            DecryptionResponse::Error(e) => panic!("{}", e),
        }
    }
}