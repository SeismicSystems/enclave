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


use crate::key_manager::key_manager::KeyManager;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorShare {
    pub share: [u8; 32],
}

impl FromStr for OperatorShare {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err(format!("Expected 32 bytes, got {}", bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(OperatorShare { share: arr })
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

    pub fn build_from_operator_shares(self) -> Result<KeyManager> {
        let master_key_bytes = [0u8; 32];
        // TODO: derive master key from shares
        let km = KeyManager::new(master_key_bytes)?;
        Ok(km)
    }

    pub fn build_from_os_rng() -> Result<KeyManager> {
        let mut rng = OsRng;
        let mut rng_bytes = [0u8; 32];
        rng.try_fill_bytes(&mut rng_bytes)?;

        let km = KeyManager::new(rng_bytes)?;
        Ok(km)
    }

    pub fn mock() -> Result<KeyManager> {
        let km = KeyManager::new([0u8; 32])?;
        Ok(km)
    }
}