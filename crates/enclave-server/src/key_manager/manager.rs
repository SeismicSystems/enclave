use super::NetworkKeyProvider;

use hkdf::Hkdf;
use sha2::Sha256;
use std::sync::Mutex;
use strum_macros::EnumIter;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Salt used during HKDF key derivation for purpose-specific keys.
const PURPOSE_DERIVE_SALT: &[u8] = b"seismic-purpose-derive-salt";
/// Prefix used in domain separation when deriving purpose-specific keys.
const PREFIX: &str = "seismic-purpose";

/// Represents a derived key used for specific cryptographic purposes.
///
/// Implements [`Zeroize`] and [`ZeroizeOnDrop`] to ensure the memory is cleared
/// when the value is dropped or explicitly zeroized.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
struct Key(pub Vec<u8>);
impl Key {
    /// Creates a new `Key` from the given byte vector.
    ///
    /// This is primarily used internally by the key manager when deriving keys.
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}
impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

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

/// Key manager for handling purpose-specific derived keys from a single root key.
///
/// Keys are derived using HKDF-SHA256 with domain separation.
/// This struct supports retrieving keys. See KeyPurpose for the intended usages
pub struct KeyManager {
    root_key: Mutex<Key>,
}
impl KeyManager {
    /// Derives a key for a specific `KeyPurpose`
    ///
    /// # Errors
    ///
    /// Returns an error if HKDF expansion fails (though this is unlikely with correct parameters).
    fn derive_purpose_key(&self, purpose: KeyPurpose, epoch: u64) -> Result<Key, anyhow::Error> {
        let root_guard = self.root_key.lock().unwrap();
        let hk = Hkdf::<Sha256>::new(Some(PURPOSE_DERIVE_SALT), root_guard.as_ref());
        let mut info = purpose.domain_separator();
        info.extend_from_slice(&epoch.to_be_bytes());
        let mut derived_key = vec![0u8; 32];
        hk.expand(&info, &mut derived_key)
            .expect("32 is a valid length for Sha256 to output");
        let key = Key::new(derived_key);

        Ok(key)
    }

    /// Retrieves a purpose specific key derived from the root key
    ///
    /// Current implementation simply re-derives the key each time this function is called
    /// Future implementations may cache the derived key, in which case this function will do more
    fn get_purpose_key(&self, purpose: KeyPurpose, epoch: u64) -> Result<Key, anyhow::Error> {
        let key = self.derive_purpose_key(purpose, epoch)?;
        Ok(key)
    }
}
impl NetworkKeyProvider for KeyManager {
    /// Constructs a new `KeyManager` from a 32-byte root key.
    fn new(root_key_bytes: [u8; 32]) -> Self {
        let km = Self {
            root_key: Mutex::new(Key(root_key_bytes.to_vec())),
        };
        km
    }

    /// Sets the root key for the key manager, replacing any existing key material.
    fn set_root_key(&self, new_root_key: [u8; 32]) {
        let mut root_guard = self.root_key.lock().unwrap();
        *root_guard = Key(new_root_key.to_vec());
    }

    /// Retrieves the secp256k1 secret key for transaction I/O signing.
    fn get_tx_io_sk(&self, epoch: u64) -> secp256k1::SecretKey {
        let key = self
            .get_purpose_key(KeyPurpose::TxIo, epoch)
            .expect("KeyManager should always have a snapshot key");
        secp256k1::SecretKey::from_slice(key.as_ref())
            .expect("retrieved secp256k1 secret key should be valid")
    }

    /// Retrieves the secp256k1 public key corresponding to the TxIo secret key.
    fn get_tx_io_pk(&self, epoch: u64) -> secp256k1::PublicKey {
        let key = self
            .get_purpose_key(KeyPurpose::TxIo, epoch)
            .expect("KeyManager should always have a snapshot key");
        let sk = secp256k1::SecretKey::from_slice(key.as_ref())
            .expect("retrieved secp256k1 secret key should be valid");

        secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk)
    }

    /// Retrieves the Schnorrkel keypair used for randomness generation.
    fn get_rng_keypair(&self, epoch: u64) -> schnorrkel::keys::Keypair {
        let mini_key = self
            .get_purpose_key(KeyPurpose::RngPrecompile, epoch)
            .expect("KeyManager should always have a snapshot key");
        let mini_key_bytes = mini_key.as_ref();
        let mini_secret_key = schnorrkel::MiniSecretKey::from_bytes(mini_key_bytes)
            .expect("mini_secret_key should be valid");
        mini_secret_key
            .expand(schnorrkel::ExpansionMode::Uniform)
            .into()
    }

    /// Retrieves the AES-256-GCM encryption key used for snapshot operations.
    fn get_snapshot_key(&self, epoch: u64) -> aes_gcm::Key<aes_gcm::Aes256Gcm> {
        let key = self
            .get_purpose_key(KeyPurpose::Snapshot, epoch)
            .expect("KeyManager should always have a snapshot key");
        let bytes: [u8; 32] = key.as_ref().try_into().expect("Key should be 32 bytes");
        bytes.into()
    }
    /// Retrieves a copy of the root secp256k1 secret key used for key management.
    fn get_root_key(&self) -> [u8; 32] {
        let root_guard = self.root_key.lock().unwrap();
        let bytes: [u8; 32] = root_guard.as_ref().try_into().unwrap();
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    #[test]
    fn test_all_purpose_keys_are_initialized() {
        let key_manager = KeyManager::new([0u8; 32]);

        for purpose in KeyPurpose::iter() {
            let key = key_manager.get_purpose_key(purpose, 0).unwrap();
            assert!(!key.as_ref().is_empty());
        }
    }

    #[test]
    fn test_purpose_specific_keys_are_consistent() {
        let key_manager = KeyManager::new([0u8; 32]);
        let key_a = key_manager
            .get_purpose_key(KeyPurpose::Snapshot, 0)
            .unwrap();
        let key_b = key_manager
            .get_purpose_key(KeyPurpose::Snapshot, 0)
            .unwrap();
        assert_eq!(key_a.as_ref(), key_b.as_ref());
    }

    #[test]
    fn test_epoch_key_rotation() {
        let key_manager = KeyManager::new([0u8; 32]);
        let key_a = key_manager
            .get_purpose_key(KeyPurpose::Snapshot, 0)
            .unwrap();
        let key_b = key_manager
            .get_purpose_key(KeyPurpose::Snapshot, 1)
            .unwrap();
        assert_ne!(key_a.as_ref(), key_b.as_ref());
    }
}
