use serde::{Deserialize, Serialize};
use bincode;

#[derive(Debug, Serialize, Deserialize)]
pub struct GenesisData {
    pub io_pk: secp256k1::PublicKey,
}

impl GenesisData {
    // Serialize the struct to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Failed to serialize")
    }

    // Deserialize the struct from bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        bincode::deserialize(bytes).expect("Failed to deserialize")
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenesisDataResponse {
    pub data: GenesisData,
    pub evidence: Vec<u8>,
}