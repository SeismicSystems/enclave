use serde::{Deserialize, Serialize};

// Struct for serializing the io encryption request
#[derive(Debug, Serialize, Deserialize)]
pub struct IoEncryptionRequest {
    pub msg_sender: secp256k1::PublicKey,
    pub data: Vec<u8>,
    pub nonce: u64,
}

// Struct for serializing the io encryption response
#[derive(Debug, Serialize, Deserialize)]
pub struct IoEncryptionResponse {
    pub encrypted_data: Vec<u8>,
}

// Struct for serializing the io decryption request
#[derive(Debug, Serialize, Deserialize)]
pub struct IoDecryptionRequest {
    pub msg_sender: secp256k1::PublicKey,
    pub data: Vec<u8>,
    pub nonce: u64,
}

// Struct for serializing the io decryption response
#[derive(Debug, Serialize, Deserialize)]
pub struct IoDecryptionResponse {
    pub decrypted_data: Vec<u8>,
}