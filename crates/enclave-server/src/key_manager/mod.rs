mod builder;
mod manager;

// re-export important types
pub use builder::KeyManagerBuilder;
pub use manager::KeyManager;

use auto_impl::auto_impl;

/// Trait for providing access to derived keys used in networking and other runtime logic.
///
/// Used to abstract over how keys are retrieved (e.g., real or mocked key managers).
#[auto_impl(&, Arc)]
pub trait NetworkKeyProvider: Sync {
    /// Sets the root key for the key manager, replacing any existing key material.
    /// This update should propogate so that all derived keys are recalculated
    /// based on the newly provided root key.
    ///
    /// This method should use interior mutability, e.g. Mutex, to allow
    /// mutation without requiring a mutable reference to the key manager.
    /// This keeps the higher-level API ergonomics clean by avoiding the need
    /// for `&mut self` or external synchronization primitives.
    fn set_root_key(&self, root_key: [u8; 32]);

    /// Retrieves the root secp256k1 secret key used for key management.
    fn get_root_key(&self) -> [u8; 32];

    /// Retrieves the secp256k1 secret key used for transaction I/O.
    fn get_tx_io_sk(&self, epoch: u64) -> secp256k1::SecretKey;

    /// Retrieves the secp256k1 public key corresponding to the transaction I/O secret key.
    fn get_tx_io_pk(&self, epoch: u64) -> secp256k1::PublicKey;

    /// Retrieves the Schnorrkel keypair used for generating randomness.
    fn get_rng_keypair(&self, epoch: u64) -> schnorrkel::keys::Keypair;

    /// Retrieves the AES-256-GCM encryption key used for snapshot encryption.
    fn get_snapshot_key(&self, epoch: u64) -> aes_gcm::Key<aes_gcm::Aes256Gcm>;
}
