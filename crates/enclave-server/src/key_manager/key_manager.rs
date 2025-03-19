use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use seismic_enclave::get_unsecure_sample_secp256k1_sk;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::utils::tdx_evidence_helpers::{get_tdx_quote, parse_tdx_quote, Evidence};

// Constants
const TEST_ENV_SEED: &[u8] = b"devnet-test-environment-seed-for-development-only";
const TEE_INFO_SALT: &[u8] = b"devnet-tee-info-salt-v1";
const MASTER_KEY_INFO: &[u8] = b"devnet-master-key-derivation-v1";

// Quote parsing constants
const QUOTE_HEADER_SIZE: usize = 48;

//Key purpose Constants
pub const PURPOSE_AES: &str = "SEISMIC-AES";

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorShare {
    pub id: String,
    pub share: Vec<u8>, 
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

pub struct KeyManagerBuilder {
    operator_shares: Vec<OperatorShare>,
}

impl KeyManagerBuilder {
    pub fn new() -> Self {
        Self {
            operator_shares: Vec::new(),
        }
    }

    //For now, there is one other share at most
    pub fn with_operator_share(mut self, share: OperatorShare) -> Self {
        self.operator_shares.push(share);
        self
    }

    pub fn build(self) -> Result<KeyManager> {
        KeyManager::new_with_shares(&self.operator_shares)
    }
}

// Key manager state
pub struct KeyManager {
    master_key: Secret,
    purpose_keys: HashMap<String, Key>,
}

impl KeyManager {
    pub fn new_with_shares(operator_shares: &[OperatorShare]) -> Result<Self> {
        if operator_shares.len() != 1 {
            return Err(anyhow!(
                "At least one operator share is required in production"
            ));
        }

        let tee_share = Self::derive_tee_share()?;

        let mut share_bytes = Vec::with_capacity(operator_shares.len());
        for share in operator_shares {
            let bytes = hex::decode(&share.share)
                .map_err(|_| anyhow!("Invalid share format: {}", share.id))?;
            share_bytes.push(bytes);
        }

        // Combine TEE share with operator shares using HKDF
        let mut combined_input = Vec::new();
        combined_input.extend_from_slice(tee_share.as_ref());
        for share in &share_bytes {
            combined_input.extend_from_slice(share);
        }

        // Use HKDF to derive the master key
        let hk = Hkdf::<Sha256>::new(None, &combined_input);
        let mut master_key_bytes = [0u8; 32];
        hk.expand(MASTER_KEY_INFO, &mut master_key_bytes)
            .map_err(|_| anyhow!("HKDF expand failed for master key"))?;

        log::info!(
            "Key manager initialized with TEE share and {} operator shares",
            operator_shares.len()
        );

        Ok(Self {
            master_key: Secret::new(master_key_bytes),
            purpose_keys: HashMap::new(),
        })
    }

    /// Create a builder for the KeyManager
    pub fn builder() -> KeyManagerBuilder {
        KeyManagerBuilder::new()
    }

    /// Create a new KeyManager with test shares (for development only)
    pub fn new_with_test_shares() -> Self {
        KeyManager {
            master_key: Secret::new(get_unsecure_sample_secp256k1_sk().as_ref()),
            purpose_keys: HashMap::new(),
        }
    }

    /// Derive a deterministic TEE share from MRTD
    fn derive_tee_share() -> Result<Secret> {
        match get_tdx_quote() {
            Ok(quote) => {
                let mrtd = quote.rtmr_3();
                let hk = Hkdf::<Sha256>::new(Some(TEE_INFO_SALT), mrtd);
                let mut share = [0u8; 32];
                hk.expand(b"tee-share-for-key-derivation", &mut share)
                    .map_err(|_| anyhow!("HKDF expand failed"))?;
                
                log::info!("Derived TEE share from TDX MRTD measurement");
                return Ok(Secret::new(share));
            }
            Err(e) => {
                log::warn!("Failed to get TDX quote: {}", e);
                e
            }
        }
    }


    /// Get a purpose-specific key
    pub fn get_key(&mut self, purpose: &str) -> Result<Key> {
        // Check if we have a valid cached key
        if let Some(key) = self.purpose_keys.get(purpose) {
            return Ok(key.clone());
        }

        // Use HKDF to derive the purpose-specific key
        let purpose_info = format!("devnet-{}-key-v1", purpose).into_bytes();
        let hk = Hkdf::<Sha256>::new(None, self.master_key.as_ref());
        let mut derived_key = vec![0u8; 32];
        hk.expand(&purpose_info, &mut derived_key)
            .map_err(|_| anyhow!("HKDF expand failed for purpose key"))?;
        
        // Create and cache the key
        let key = Key::new(derived_key);
        self.purpose_keys.insert(purpose.to_string(), key.clone());

        Ok(key)
    }

    pub fn get_aes_key(&mut self) -> Result<Key> {
        self.get_key(PURPOSE_AES)
    }
}

// Example usage
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_manager_direct_constructor() {
        // Create a key manager instance directly
        let mut key_manager = KeyManager::new_with_test_shares();
        
        // Get an AES key
        let aes_key = key_manager.get_aes_key().unwrap();
        
        // Key should have 32 bytes (256 bits)
        assert_eq!(aes_key.bytes.len(), 32);
    }

    #[test]
    fn test_key_manager_builder() {
        // Create a key manager using the builder pattern
        let mut key_manager = KeyManager::builder()
            .with_operator_share(OperatorShare {
                id: "share-seismic".to_string(),
                share: vec![1u8; 32],
            })
            .build()
            .unwrap();

        // Get an AES key
        let aes_key = key_manager.get_aes_key().unwrap();
        
        // Key should have 32 bytes (256 bits)
        assert_eq!(aes_key.bytes.len(), 32);
    }
}
