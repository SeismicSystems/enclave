use crate::key_manager::{Key, Secret};

use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashMap;
use strum_macros::EnumIter;
use strum::IntoEnumIterator;
use crate::key_manager::NetworkKeyProvider;

// MasterKey Constants
const TEE_DOMAIN_SEPARATOR: &[u8] = b"seismic-tee-domain-separator";
const MASTER_KEY_DOMAIN_INFO: &[u8] = b"seismic-master-key-derivation";

// KeyPurpose constants
const PREFIX: &str = "seismic-purpose";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter)]
pub enum KeyPurpose {
    Snapshot,
    RngPrecompile,
    Secp256k1, // TODO: rename to tx_io?
    Schnorrkel, // todo: rename to  RNG precompile?
}

impl KeyPurpose {
    fn label(&self) -> &'static str {
        match self {
            KeyPurpose::Snapshot => "snapshot",
            KeyPurpose::RngPrecompile => "rng-precompile",
            KeyPurpose::Secp256k1 => "secp256k1",
            KeyPurpose::Schnorrkel => "schnorrkel",
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
        let mut km = Self {
            master_key: Secret::new(master_key_bytes),
            purpose_keys: HashMap::new(), // purpose keys are derived on demand
        };
        km.derive_all_purpose_keys()?;
        Ok(km)
    }

    fn derive_all_purpose_keys(&mut self) -> Result<()> {
        for purpose in KeyPurpose::iter() {
            self.derive_purpose_key(purpose)?;
        }
        Ok(())
    }

    // TODO: double check this uses hk correctly, e.g. if string should be in salt or info
    // TODO: consider adding a constant useful for rotation, ex epoch to the info field
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

    /// Get a purpose-specific key.
    /// Derives the key if it doesn't exist yet
    fn get_key(&self, purpose: KeyPurpose) -> Result<Key> {
        if let Some(key) = self.purpose_keys.get(&purpose) {
            return Ok(key.clone());
        } else {
            anyhow::bail!("KeyManager does not have a key for purpose {:?}", purpose);
        }
    } 
}

// TODO: implement NetworkKeyProvider for KeyManager
// TODO: replace get_key KeyPurpose
impl NetworkKeyProvider for KeyManager {
    fn get_secp256k1_sk(&self) -> secp256k1::SecretKey {
        let key = self.get_key(KeyPurpose::Secp256k1)
            .expect("KeyManager should always have a snapshot key");
        secp256k1::SecretKey::from_slice(&key.bytes).expect("retrieved secp256k1 secret key should be valid")
    }

    fn get_secp256k1_pk(&self) -> secp256k1::PublicKey {
        let key = self.get_key(KeyPurpose::Secp256k1)
            .expect("KeyManager should always have a snapshot key");
        let sk = secp256k1::SecretKey::from_slice(&key.bytes).expect("retrieved secp256k1 secret key should be valid");
        let pk = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk);
        pk
    }

    fn get_schnorrkel_keypair(&self) -> schnorrkel::keys::Keypair {
        let mini_key_bytes = self.get_key(KeyPurpose::Schnorrkel)
            .expect("KeyManager should always have a snapshot key");
        let mini_secret_key = schnorrkel::MiniSecretKey::from_bytes(mini_key_bytes.bytes.as_slice())
            .expect("mini_secret_key should be valid");
        mini_secret_key.expand(schnorrkel::ExpansionMode::Uniform).into()
    }

    fn get_snapshot_key(&self) -> aes_gcm::Key<aes_gcm::Aes256Gcm> {
        let key = self.get_key(KeyPurpose::Snapshot)
            .expect("KeyManager should always have a snapshot key");
        let bytes: [u8; 32] = key.bytes.try_into().expect("Key should be 32 bytes");
        bytes.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_purpose_keys_are_initialized() {
        let master_key_bytes = [0u8; 32];
        let key_manager = KeyManager::new(master_key_bytes).unwrap();
        
        for purpose in KeyPurpose::iter() {
            let key = key_manager.get_key(purpose).unwrap();
            assert!(!key.bytes.is_empty());
        }
    }

    #[test]
    fn test_purpose_specific_keys_are_consistent() {
        let master_key_bytes = [0u8; 32];
        let key_manager = KeyManager::new(master_key_bytes).unwrap();
        let key_a = key_manager.get_key(KeyPurpose::Snapshot).unwrap();
        let key_b = key_manager.get_key(KeyPurpose::Snapshot).unwrap();
        assert_eq!(key_a.bytes, key_b.bytes);
    }

}
