use bincode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GenesisData {
    pub io_pk: secp256k1::PublicKey,
}

#[allow(dead_code)]
impl GenesisData {
    // Serialize the struct to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        let bytes = bincode::serialize(self)?;
        Ok(bytes)
    }

    // Deserialize the struct from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        let genesis_data = bincode::deserialize(bytes)?;
        Ok(genesis_data)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GenesisDataResponse {
    pub data: GenesisData,
    pub evidence: Vec<u8>,
}
