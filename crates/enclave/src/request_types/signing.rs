use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Secp256k1SignRequest {
    pub msg: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Secp256k1SignResponse {
    pub sig: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Secp256k1VerifyRequest {
    pub msg: Vec<u8>,
    pub sig: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Secp256k1VerifyResponse {
    pub verified: bool,
}