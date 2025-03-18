use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use log::{debug, error, info, warn};
use scroll::Pread;
use seismic_enclave::get_unsecure_sample_secp256k1_sk;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

use crate::utils::tdx_evidence_helpers::parse_tdx_quote;

// Constants
const TDX_GUEST_PATH: &str = "/dev/tdx-guest";
const TEST_ENV_SEED: &[u8] = b"devnet-test-environment-seed-for-development-only";
const TEE_INFO_SALT: &[u8] = b"devnet-tee-info-salt-v1";
const MASTER_KEY_INFO: &[u8] = b"devnet-master-key-derivation-v1";

// Quote parsing constants
const QUOTE_HEADER_SIZE: usize = 48;

//Key purpose Constants
pub const PURPOSE_AES: &str = "AES";

// Data structures for operator shares
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorShare {
    pub id: String,
    pub share: Vec<u8>, // hex-encoded share bytes
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
    master_key: Vec<u8>,
    purpose_keys: HashMap<String, Key>,
}

impl KeyManager {
    pub fn new_with_shares(operator_shares: &[OperatorShare]) -> Result<Self> {
        // In production, we require exactly one operator share for now.
        if operator_shares.len() != 1 && Self::is_tdx_environment() {
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
        combined_input.extend_from_slice(&tee_share);
        for share in &share_bytes {
            combined_input.extend_from_slice(share);
        }

        // Use HKDF to derive the master key
        let hk = Hkdf::<Sha256>::new(None, &combined_input);
        let mut master_key = vec![0u8; 32];
        hk.expand(MASTER_KEY_INFO, &mut master_key)
            .map_err(|_| anyhow!("HKDF expand failed for master key"))?;

        log::info!(
            "Key manager initialized with TEE share and {} operator shares",
            operator_shares.len()
        );

        Ok(Self {
            master_key,
            purpose_keys: HashMap::new(),
        })
    }

    /// Create a builder for the KeyManager
    pub fn builder() -> KeyManagerBuilder {
        KeyManagerBuilder::new()
    }

    /// Create a new KeyManager with test shares (for development only)
    pub fn new_with_test_shares(count: usize) -> Result<Self> {
        let test_shares = Self::generate_test_shares(count);
        Self::new_with_shares(&test_shares)
    }

    /// Check if we're running in a TDX environment
    pub fn is_tdx_environment() -> bool {
        Path::new(TDX_GUEST_PATH).exists()
    }

    /// Get TDX evidence for the current TD
    fn get_tdx_evidence() -> Result<Evidence> {
        // In a real implementation, you would use the TDX attestation API
        // to get a quote. For now, we'll simulate by looking for a cached quote.

        // Check for a cached quote file (for testing purposes)
        if let Ok(td_quote) = fs::read("/var/lib/tdx_quote.bin") {
            return Ok(Evidence { td_quote });
        }

        // Try to get a quote using tdx-attest or similar
        // This is platform dependent, so implement based on your environment
        Err(anyhow!("TDX quote not available"))
    }

    /// Derive a deterministic TEE share from MRTD
    fn derive_tee_share() -> Result<Vec<u8>> {
        if Self::is_tdx_environment() {
            match Self::get_tdx_evidence() {
                Ok(evidence) => match parse_tdx_quote(&evidence.td_quote) {
                    Ok(quote) => {
                        let mrtd = quote.get_mrtd();

                        let hk = Hkdf::<Sha256>::new(Some(TEE_INFO_SALT), mrtd);
                        let mut share = vec![0u8; 32];
                        hk.expand(b"tee-share-for-key-derivation", &mut share)
                            .map_err(|_| anyhow!("HKDF expand failed"))?;

                        log::info!("Derived TEE share from TDX MRTD measurement");
                        return Ok(share);
                    }
                    Err(e) => {
                        log::warn!("Failed to parse TDX quote: {}", e);
                    }
                },
                Err(e) => {
                    log::warn!("Failed to get TDX evidence: {}", e);
                }
            }
        }

        // Not in TDX environment, use test values
        log::warn!(
            "Not running in TDX environment - using TEST values (not secure for production)"
        );
        Self::derive_test_tee_share()
    }

    /// Derive a test TEE share
    fn derive_test_tee_share() -> Result<Vec<u8>> {
        &get_unsecure_sample_secp256k1_sk()
    }

    /// Get a purpose-specific key
    pub fn get_key(&mut self, purpose: &str, expiry_seconds: Option<u64>) -> Result<Key> {
        // Check if we have a valid cached key
        if let Some(key) = self.purpose_keys.get(purpose) {
            if key.is_valid() {
                return Ok(key.clone());
            }
        }

        // Use HKDF to derive the purpose-specific key
        let purpose_info = format!("devnet-{}-key-v1", purpose).into_bytes();
        let hk = Hkdf::<Sha256>::new(None, &self.master_key);
        let mut derived_key = vec![0u8; 32];
        hk.expand(&purpose_info, &mut derived_key)
            .map_err(|_| anyhow!("HKDF expand failed for purpose key"))?;

        // Create key with or without expiration
        let key = match expiry_seconds {
            Some(seconds) => Key::new_with_expiry(derived_key, seconds),
            None => Key::new(derived_key),
        };

        // Cache it
        self.purpose_keys.insert(purpose.to_string(), key.clone());

        Ok(key)
    }

    /// Get encryption key
    pub fn get_aes_key(&mut self, expiry_seconds: Option<u64>) -> Result<Key> {
        self.get_key(PURPOSE_AES, expiry_seconds)
    }

    /// Generate test operator shares (for development only)
    pub fn generate_test_shares(count: usize) -> Vec<OperatorShare> {
        if Self::is_tdx_environment() {
            log::warn!("Generating test shares in TDX environment - NOT SECURE");
        }

        // Use a different RNG interface that's easier to work with
        use rand::{thread_rng, RngCore};
        let mut rng = thread_rng();

        (0..count)
            .map(|i| {
                let mut bytes = vec![0u8; 32];
                rng.fill_bytes(&mut bytes);

                OperatorShare {
                    id: format!("test-share-{}", i + 1),
                    share: hex::encode(bytes),
                }
            })
            .collect()
    }
}

// Example usage
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_manager_direct_constructor() {
        // Generate test shares for development
        let test_shares = KeyManager::generate_test_shares(3);

        // Create a key manager instance directly
        let mut key_manager = KeyManager::new_with_shares(&test_shares).unwrap();

        // Get an AES key
        let aes_key = key_manager.get_aes_key(Some(3600)).unwrap();

        // Ensure the key is valid
        assert!(aes_key.is_valid());

        // Key should have 32 bytes (256 bits)
        assert_eq!(aes_key.bytes.len(), 32);
    }

    #[test]
    fn test_key_manager_builder() {
        // Create a key manager using the builder pattern
        let mut key_manager = KeyManager::builder()
            .with_operator_share(OperatorShare {
                id: "share-1".to_string(),
                share: hex::encode(vec![1u8; 32]),
            })
            .with_operator_share(OperatorShare {
                id: "share-2".to_string(),
                share: hex::encode(vec![2u8; 32]),
            })
            .build()
            .unwrap();

        // Get an AES key
        let aes_key = key_manager.get_aes_key(None).unwrap();

        // Key should have 32 bytes (256 bits)
        assert_eq!(aes_key.bytes.len(), 32);
    }

    #[test]
    fn test_key_manager_with_test_shares() {
        // Create a key manager with test shares
        let mut key_manager = KeyManager::new_with_test_shares(2).unwrap();

        // Get an AES key with expiry
        let aes_key = key_manager.get_aes_key(Some(3600)).unwrap();

        // Key should be valid
        assert!(aes_key.is_valid());
    }
}
