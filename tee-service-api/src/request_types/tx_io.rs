use serde::{Deserialize, Serialize};

/// Struct representing the IO encryption request.
///
/// # Fields
/// * `encryption_pubkey` - The ephemeral secp256k1 public key.
/// * `data` - The data to be encrypted, represented as a `Vec<u8>`.
/// * `nonce` - A 64-bit unsigned integer used as a nonce in the encryption process.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IoEncryptionRequest {
    pub key: secp256k1::PublicKey,
    pub data: Vec<u8>,
    pub nonce: u64,
}

/// Struct representing the IO encryption response.
///
/// # Fields
/// * `encrypted_data` - The encrypted data, represented as a `Vec<u8>`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IoEncryptionResponse {
    pub encrypted_data: Vec<u8>,
}

/// Struct representing the IO decryption request.
///
/// # Fields
/// * `encryption_pubkey` - The ephemeral secp256k1 public key.
/// * `data` - The encrypted data to be decrypted, represented as a `Vec<u8>`.
/// * `nonce` - A 64-bit unsigned integer used as a nonce in the decryption process.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IoDecryptionRequest {
    pub key: secp256k1::PublicKey,
    pub data: Vec<u8>,
    pub nonce: u64,
}

/// Struct representing the IO decryption response.
///
/// # Fields
/// * `decrypted_data` - The decrypted data, represented as a `Vec<u8>`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IoDecryptionResponse {
    pub decrypted_data: Vec<u8>,
}
