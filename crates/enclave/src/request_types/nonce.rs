use aes_gcm::{
    aead::{generic_array::GenericArray, AeadCore},
    Aes256Gcm,
};
use serde::{Deserialize, Serialize};

use crate::u64_to_generic_u8_array;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Nonce {
    U64(u64),
    Vec(Vec<u8>),
    Bytes([u8; 12]),
}

impl From<u64> for Nonce {
    fn from(value: u64) -> Self {
        Self::U64(value)
    }
}

impl From<Vec<u8>> for Nonce {
    fn from(value: Vec<u8>) -> Self {
        Self::Vec(value)
    }
}

impl From<[u8; 12]> for Nonce {
    fn from(value: [u8; 12]) -> Self {
        Self::Bytes(value)
    }
}

impl Into<Vec<u8>> for Nonce {
    fn into(self) -> Vec<u8> {
        match self {
            Self::U64(value) => u64_to_generic_u8_array(value).to_vec(),
            Self::Vec(value) => value,
            Self::Bytes(value) => value.to_vec(),
        }
    }
}

impl TryInto<GenericArray<u8, <Aes256Gcm as AeadCore>::NonceSize>> for Nonce {
    type Error = anyhow::Error;

    fn try_into(
        self,
    ) -> Result<GenericArray<u8, <Aes256Gcm as AeadCore>::NonceSize>, anyhow::Error> {
        let nonce_vec: Vec<u8> = self.into();
        if nonce_vec.len() != 12 {
            return Err(anyhow::anyhow!("Nonce must be exactly 12 bytes (92 bits)"));
        }
        Ok(GenericArray::<u8, <Aes256Gcm as AeadCore>::NonceSize>::clone_from_slice(&nonce_vec))
    }
}
