use aes_gcm::{
    aead::{generic_array::GenericArray, AeadCore},
    Aes256Gcm,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Nonce {
    U64(u64),
    Vec(Vec<u8>),
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

impl Into<Vec<u8>> for Nonce {
    fn into(self) -> Vec<u8> {
        match self {
            Self::U64(value) => u64_to_generic_u8_array(value).to_vec(),
            Self::Vec(value) => value,
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

/// Converts a `u64` nonce to a `GenericArray<u8, N>`, where `N` is the size expected by AES-GCM.
///
/// This function takes a `u64` nonce and converts it into a generic byte array
/// with the appropriate size for AES-GCM encryption.
///
/// # Arguments
/// * `nonce` - A 64-bit unsigned integer representing the nonce.
///
/// # Returns
/// A `GenericArray<u8, N>` where `N` is the expected nonce size for AES-GCM encryption.
pub fn u64_to_generic_u8_array(nonce: u64) -> GenericArray<u8, <Aes256Gcm as AeadCore>::NonceSize> {
    let mut nonce_bytes = nonce.to_be_bytes().to_vec();
    let crypto_nonce_size = GenericArray::<u8, <Aes256Gcm as AeadCore>::NonceSize>::default().len();
    nonce_bytes.resize(crypto_nonce_size, 0); // pad to the expected size
    GenericArray::clone_from_slice(&nonce_bytes)
}
