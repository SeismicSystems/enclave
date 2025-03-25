use crate::key_manager::{Key, Secret};

use crate::key_manager::NetworkKeyProvider;
use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashMap;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

/// Salt used during HKDF key derivation for purpose-specific keys.
const PURPOSE_DERIVE_SALT: &[u8] = b"seismic-purpose-derive-salt";
/// Prefix used in domain separation when deriving purpose-specific keys.
const PREFIX: &str = "seismic-purpose";

/// Enum representing the intended usage ("purpose") of a derived key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter)]
pub enum KeyPurpose {
    Snapshot,
    RngPrecompile,
    TxIo,
}

impl KeyPurpose {
    /// Returns the short string label for the purpose.
    fn label(&self) -> &'static str {
        match self {
            KeyPurpose::Snapshot => "snapshot",
            KeyPurpose::RngPrecompile => "rng-precompile",
            KeyPurpose::TxIo => "tx-io",
        }
    }

    /// Returns the domain separator for this purpose, used in HKDF expansion.
    pub fn domain_separator(&self) -> Vec<u8> {
        format!("{PREFIX}-{}", self.label()).into_bytes()
    }
}

/// Key manager for handling purpose-specific derived keys from a single master key.
///
/// Keys are derived using HKDF-SHA256 with domain separation.
/// This struct supports retrieving keys. See KeyPurpose for the intended usages
pub struct KeyManager {
    master_key: Secret,
    //no-thread-safety yet
    purpose_keys: HashMap<KeyPurpose, Key>,
}

impl KeyManager {
    /// Constructs a new `KeyManager` from a 32-byte master key.
    ///
    /// This will immediately derive all known purpose keys.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn new(master_key_bytes: [u8; 32]) -> Result<Self> {
        let mut km = Self {
            master_key: Secret::new(master_key_bytes),
            purpose_keys: HashMap::new(), // purpose keys are derived on demand
        };
        km.derive_all_purpose_keys()?;
        Ok(km)
    }

    /// Iterates over KeyPurpose and derives all purpose keys.
    fn derive_all_purpose_keys(&mut self) -> Result<()> {
        for purpose in KeyPurpose::iter() {
            self.derive_purpose_key(purpose)?;
        }
        Ok(())
    }

    /// Derives a key for a specific `KeyPurpose` and stores it internally.
    ///
    /// # Errors
    ///
    /// Returns an error if HKDF expansion fails (though this is unlikely with correct parameters).
    fn derive_purpose_key(&mut self, purpose: KeyPurpose) -> Result<Key> {
        let hk = Hkdf::<Sha256>::new(Some(PURPOSE_DERIVE_SALT), &self.master_key.as_ref());
        let mut derived_key = vec![0u8; 32];
        hk.expand(&purpose.domain_separator(), &mut derived_key)
            .expect("32 is a valid length for Sha256 to output");
        let key = Key::new(derived_key);
        self.purpose_keys.insert(purpose, key.clone());

        Ok(key)
    }

    /// Retrieves a previously derived key for a given purpose.
    ///
    /// # Errors
    ///
    /// Returns an error if the key has not been derived.
    fn get_key(&self, purpose: KeyPurpose) -> Result<Key> {
        if let Some(key) = self.purpose_keys.get(&purpose) {
            return Ok(key.clone());
        } else {
            anyhow::bail!("KeyManager does not have a key for purpose {:?}", purpose);
        }
    }
}

impl NetworkKeyProvider for KeyManager {
    /// Retrieves the secp256k1 secret key for transaction I/O signing.
    fn get_tx_io_sk(&self) -> secp256k1::SecretKey {
        let key = self
            .get_key(KeyPurpose::TxIo)
            .expect("KeyManager should always have a snapshot key");
        secp256k1::SecretKey::from_slice(&key.bytes)
            .expect("retrieved secp256k1 secret key should be valid")
    }

    /// Retrieves the secp256k1 public key corresponding to the TxIo secret key.
    fn get_tx_io_pk(&self) -> secp256k1::PublicKey {
        let key = self
            .get_key(KeyPurpose::TxIo)
            .expect("KeyManager should always have a snapshot key");
        let sk = secp256k1::SecretKey::from_slice(&key.bytes)
            .expect("retrieved secp256k1 secret key should be valid");
        let pk = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk);
        pk
    }

    /// Retrieves the Schnorrkel keypair used for randomness generation.
    fn get_rng_keypair(&self) -> schnorrkel::keys::Keypair {
        let mini_key_bytes = self
            .get_key(KeyPurpose::RngPrecompile)
            .expect("KeyManager should always have a snapshot key");
        let mini_secret_key =
            schnorrkel::MiniSecretKey::from_bytes(mini_key_bytes.bytes.as_slice())
                .expect("mini_secret_key should be valid");
        mini_secret_key
            .expand(schnorrkel::ExpansionMode::Uniform)
            .into()
    }

    /// Retrieves the AES-256-GCM encryption key used for snapshot operations.
    fn get_snapshot_key(&self) -> aes_gcm::Key<aes_gcm::Aes256Gcm> {
        let key = self
            .get_key(KeyPurpose::Snapshot)
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
