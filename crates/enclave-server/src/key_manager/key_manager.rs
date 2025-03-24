use anyhow::{anyhow, Result};
use std::str::FromStr;
use rand::rngs::OsRng;
use rand::TryRngCore;
use hkdf::Hkdf;
use seismic_enclave::get_unsecure_sample_secp256k1_sk;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

use az_tdx_vtpm::is_tdx_cvm;
use crate::utils::tdx_evidence_helpers::get_tdx_quote;

// MasterKey Constants
const TEE_DOMAIN_SEPARATOR: &[u8] = b"seismic-tee-domain-separator";
const MASTER_KEY_DOMAIN_INFO: &[u8] = b"seismic-master-key-derivation";

// KeyPurpose constants
const PREFIX: &str = "seismic-purpose";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyPurpose {
    Aes,
    RngPrecompile,
}

impl KeyPurpose {
    fn label(&self) -> &'static str {
        match self {
            KeyPurpose::Aes => "aes",
            KeyPurpose::RngPrecompile => "rng-precompile",
        }
    }

    pub fn domain_separator(&self) -> Vec<u8> {
        format!("{PREFIX}-{}", self.label()).into_bytes()
    }
}



#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret(pub [u8; 32]);

impl Secret {
    pub fn new(data: [u8; 32]) -> Self {
        Secret(data)
    }

    pub fn empty() -> Self {
        Secret([0u8; 32])
    }
    
    pub fn from_vec(vec: Vec<u8>) -> Result<Self> {
        if vec.len() != 32 {
            return Err(anyhow!("Invalid secret size: expected 32 bytes, got {}", vec.len()));
        }
        let mut data = [0u8; 32];
        data.copy_from_slice(&vec);
        Ok(Secret(data))
    }
}

impl AsRef<[u8]> for Secret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct Key {
    pub bytes: Vec<u8>,
}

impl Key {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

// Key manager state.
pub struct KeyManager {
    master_key: Secret,
    //no-thread-safety yet
    purpose_keys: HashMap<KeyPurpose, Key>,
}

impl KeyManager {
    pub fn new() -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(None, &[]);
        let mut master_key_bytes = [0u8; 32];
        hk.expand(MASTER_KEY_DOMAIN_INFO, &mut master_key_bytes)
            .map_err(|_| anyhow!("HKDF expand failed for master key"))?;

        Ok(Self {
            master_key: Secret::new(master_key_bytes),
            purpose_keys: HashMap::new(),
        })
    }

    /// Get a purpose-specific key.
    fn get_key(&mut self, purpose: KeyPurpose) -> Result<Key> {
        if let Some(key) = self.purpose_keys.get(&purpose) {
            return Ok(key.clone());
        }

        let hk = Hkdf::<Sha256>::new(None, self.master_key.as_ref());
        let mut derived_key = vec![0u8; 32];
        hk.expand(&purpose.domain_separator(), &mut derived_key)
            .map_err(|_| anyhow!("HKDF expand failed for purpose key"))?;
        
        let key = Key::new(derived_key);
        self.purpose_keys.insert(purpose, key.clone());

        Ok(key)
    }

    pub fn get_aes_key(&mut self) -> Result<Key> {
        self.get_key(KeyPurpose::Aes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_secret_from_vec_valid() {
        let vec_32 = vec![1u8; 32];
        let secret = Secret::from_vec(vec_32).unwrap();
        assert_eq!(secret.as_ref().len(), 32);
    }

    #[test]
    fn test_secret_from_vec_invalid_length() {
        let vec_16 = vec![1u8; 16];
        let res = Secret::from_vec(vec_16);

        assert!(res.is_err(), "Expected error for invalid secret size");

        if let Err(e) = res {
            let msg = e.to_string();
            assert!(msg.contains("Invalid secret size"), "Unexpected error message: {}", msg);
        }
    }

    #[test]
    fn test_key_manager_direct_constructor() {
        let mut key_manager = KeyManager::new().unwrap();
        let aes_key = key_manager.get_aes_key().unwrap();
        assert_eq!(aes_key.bytes.len(), 32);
    }

    #[test]
    #[serial]
    fn test_purpose_specific_keys_are_consistent() {
        let mut key_manager = KeyManager::new().unwrap();
        let key_a = key_manager.get_key(KeyPurpose::Aes).unwrap();
        let key_b = key_manager.get_key(KeyPurpose::Aes).unwrap();
        assert_eq!(key_a.bytes, key_b.bytes);
    }
}
