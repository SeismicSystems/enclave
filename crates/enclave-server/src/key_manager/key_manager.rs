use anyhow::{anyhow, Result};
use rand::rngs::OsRng;
use hkdf::Hkdf;
use seismic_enclave::get_unsecure_sample_secp256k1_sk;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

use az_tdx_vtpm::is_tdx_cvm;
use crate::utils::tdx_evidence_helpers::get_tdx_quote;

// Constants
const TEE_DOMAIN_SEPARATOR: &[u8] = b"devnet-tee-domain-separator-v1";
const MASTER_KEY_DOMAIN_INFO: &[u8] = b"devnet-master-key-derivation-v1";

// Key purpose Constant
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
    pub share: [u8; 32],
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

    // For now, there is one other share at most.
    pub fn with_operator_share(mut self, share: OperatorShare) -> Self {
        self.operator_shares.push(share);
        self
    }

    pub fn build(self) -> Result<KeyManager> {
        KeyManager::new_with_shares(&self.operator_shares)
    }
}

// Key manager state.
pub struct KeyManager {
    master_key: Secret,
    purpose_keys: HashMap<String, Key>,
}

impl KeyManager {
    pub fn new_with_shares(operator_shares: &[OperatorShare]) -> Result<Self> {
        assert!(is_tdx_cvm()?, "TDX CVM is required for key manager");
        if operator_shares.len() != 1 {
            return Err(anyhow!(
                "At least one operator share is required in production"
            ));
        }

        let tee_share = Self::derive_tee_share()?;

        let mut share_bytes = Vec::with_capacity(operator_shares.len());
        for share in operator_shares {
            let bytes = share
                .share
                .iter()
                .flat_map(|&x| x.to_be_bytes())
                .collect::<Vec<u8>>();
            share_bytes.push(bytes);
        }

        // Combine TEE share with operator shares using HKDF.
        let mut combined_input = Vec::new();
        combined_input.extend_from_slice(tee_share.as_ref());
        for share in &share_bytes {
            combined_input.extend_from_slice(share);
        }

        // Use HKDF to derive the master key.
        let hk = Hkdf::<Sha256>::new(None, &combined_input);
        let mut master_key_bytes = [0u8; 32];
        hk.expand(MASTER_KEY_DOMAIN_INFO, &mut master_key_bytes)
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

    /// Create a builder for the KeyManager.
    pub fn builder() -> KeyManagerBuilder {
        KeyManagerBuilder::new()
    }

    /// Create a new KeyManager with test shares (for development only).
    pub fn new_with_test_shares() -> Self {
        KeyManager {
            master_key: Secret::new(*get_unsecure_sample_secp256k1_sk().as_ref()),
            purpose_keys: HashMap::new(),
        }
    }

    fn derive_tee_share() -> Result<Secret> {
        let binding = get_tdx_quote()?;
        let mrtd = binding.mrtd();

        let mut rng = OsRng;
        let mut rng_bytes = [0u8; 32];
        rng.try_fill_bytes(&mut rng_bytes)?;

        // Combine the MRTD measurement with the 32-byte RNG output.
        // Concatenation preserves the entropy from both sources.
        let mut combined_input = Vec::with_capacity(mrtd.len() + rng_bytes.len());
        combined_input.extend_from_slice(mrtd);
        combined_input.extend_from_slice(&rng_bytes);

        // Use HKDF to extract a uniformly random 32-byte secret from the combined input.
        let hk = Hkdf::<Sha256>::new(Some(TEE_DOMAIN_SEPARATOR), &combined_input);
        let mut share = [0u8; 32];
        hk.expand(b"tee-share-for-key-derivation", &mut share)
            .map_err(|_| anyhow!("HKDF expand failed"))?;

        rng_bytes.zeroize();
        combined_input.zeroize();

        Ok(Secret::new(share))
    }

    /// Get a purpose-specific key.
    pub fn get_key(&mut self, purpose: &str) -> Result<Key> {
        // Return a cached key if available.
        if let Some(key) = self.purpose_keys.get(purpose) {
            return Ok(key.clone());
        }

        // Derive the purpose-specific key using HKDF.
        let purpose_info = format!("devnet-{}-key-v1", purpose).into_bytes();
        let hk = Hkdf::<Sha256>::new(None, self.master_key.as_ref());
        let mut derived_key = vec![0u8; 32];
        hk.expand(&purpose_info, &mut derived_key)
            .map_err(|_| anyhow!("HKDF expand failed for purpose key"))?;
        
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
        // Create a key manager instance directly.
        let mut key_manager = KeyManager::new_with_test_shares();
        
        // Get an AES key.
        let aes_key = key_manager.get_aes_key().unwrap();
        
        // Key should have 32 bytes (256 bits).
        assert_eq!(aes_key.bytes.len(), 32);
    }

    #[test]
    fn test_key_manager_builder() {
        // Create a key manager using the builder pattern.
        let mut key_manager = KeyManager::builder()
            .with_operator_share(OperatorShare {
                id: "share-seismic".to_string(),
                share: [1u8; 32],
            })
            .build()
            .unwrap();

        // Get an AES key.
        let aes_key = key_manager.get_aes_key().unwrap();
        
        // Key should have 32 bytes (256 bits).
        assert_eq!(aes_key.bytes.len(), 32);
    }
}
