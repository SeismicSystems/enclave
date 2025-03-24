use crate::key_manager::{Key, Secret};

use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashMap;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

// MasterKey Constants
const TEE_DOMAIN_SEPARATOR: &[u8] = b"seismic-tee-domain-separator";
const MASTER_KEY_DOMAIN_INFO: &[u8] = b"seismic-master-key-derivation";

// KeyPurpose constants
const PREFIX: &str = "seismic-purpose";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter)]
pub enum KeyPurpose {
    Aes,
    RngPrecompile,
    // TODO: IO keys, Snapshot keys
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

// Key manager state.
pub struct KeyManager {
    master_key: Secret,
    //no-thread-safety yet
    purpose_keys: HashMap<KeyPurpose, Key>,
}

impl KeyManager {
    pub fn new(master_key_bytes: [u8; 32]) -> Result<Self> {
        Ok(Self {
            master_key: Secret::new(master_key_bytes),
            purpose_keys: HashMap::new(), // purpose keys are derived on demand
        })
    }

    /// Get a purpose-specific key.
    /// Derives the key if it doesn't exist yet
    fn get_key(&mut self, purpose: KeyPurpose) -> Result<Key> {
        if let Some(key) = self.purpose_keys.get(&purpose) {
            return Ok(key.clone());
        } else {
            self.derive_purpose_key(purpose)
        }
    }  

    // TODO: double check this uses hk correctly, e.g. if string should be in salt or info
    fn derive_purpose_key(&mut self, purpose: KeyPurpose) -> Result<Key> {
        let ikm = self.master_key.as_ref();
        let purpose_salt = purpose.domain_separator();
        let info = [];

        let hk = Hkdf::<Sha256>::new(Some(&purpose_salt), &ikm);
        let mut derived_key = vec![0u8; 32];
        hk.expand(&info, &mut derived_key)
            .expect("32 is a valid length for Sha256 to output");
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
            assert!(
                msg.contains("Invalid secret size"),
                "Unexpected error message: {}",
                msg
            );
        }
    }

    #[test]
    fn test_key_manager_direct_constructor() {
        let master_key_bytes = [0u8; 32];
        let mut key_manager = KeyManager::new(master_key_bytes).unwrap();
        let aes_key = key_manager.get_aes_key().unwrap();
        assert_eq!(aes_key.bytes.len(), 32);
    }

    #[test]
    #[serial]
    fn test_purpose_specific_keys_are_consistent() {
        let master_key_bytes = [0u8; 32];
        let mut key_manager = KeyManager::new(master_key_bytes).unwrap();
        let key_a = key_manager.get_key(KeyPurpose::Aes).unwrap();
        let key_b = key_manager.get_key(KeyPurpose::Aes).unwrap();
        assert_eq!(key_a.bytes, key_b.bytes);
    }
}
