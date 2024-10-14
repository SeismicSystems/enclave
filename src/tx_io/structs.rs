use serde::{Deserialize, Serialize};

/// Struct representing the IO encryption request.
///
/// # Fields
/// * `msg_sender` - The secp256k1 public key of the message sender.
/// * `data` - The data to be encrypted, represented as a `Vec<u8>`.
/// * `nonce` - A 64-bit unsigned integer used as a nonce in the encryption process.
#[derive(Debug, Serialize, Deserialize)]
pub struct IoEncryptionRequest {
    pub msg_sender: secp256k1::PublicKey,
    pub data: Vec<u8>,
    pub nonce: u64,
}

/// Struct representing the IO encryption response.
///
/// # Fields
/// * `encrypted_data` - The encrypted data, represented as a `Vec<u8>`.
#[derive(Debug, Serialize, Deserialize)]
pub struct IoEncryptionResponse {
    pub encrypted_data: Vec<u8>,
}

/// Struct representing the IO decryption request.
///
/// # Fields
/// * `msg_sender` - The secp256k1 public key of the message sender.
/// * `data` - The encrypted data to be decrypted, represented as a `Vec<u8>`.
/// * `nonce` - A 64-bit unsigned integer used as a nonce in the decryption process.
#[derive(Debug, Serialize, Deserialize)]
pub struct IoDecryptionRequest {
    pub msg_sender: secp256k1::PublicKey,
    pub data: Vec<u8>,
    pub nonce: u64,
}

/// Struct representing the IO decryption response.
///
/// # Fields
/// * `decrypted_data` - The decrypted data, represented as a `Vec<u8>`.
#[derive(Debug, Serialize, Deserialize)]
pub struct IoDecryptionResponse {
    pub decrypted_data: Vec<u8>,
}
