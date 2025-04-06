mod builder; // TODO: remove if not used
mod manager;

// re-export important types
pub use builder::KeyManagerBuilder;
pub use manager::KeyManager;

/// Trait for providing access to derived keys used in networking and other runtime logic.
///
/// Used to abstract over how keys are retrieved (e.g., real or mocked key managers).
pub trait NetworkKeyProvider: Sync {
    /// Constructs a new instance of the key manager.
    /// Randomly initializes a root key and derives all relevant keys. // TODO: discuss if this is good. alternative is error if not initialized
    fn new() -> Self;

    /// Sets the master key for the key manager.
    /// and re-derives all relevant keys. // TODO: discuss if this is good
    fn set_root_key(&mut self, master_key: [u8; 32]);

    /// Retrieves the root secp256k1 secret key used for key management.
    fn get_km_root_key(&self) -> [u8; 32];

    /// Retrieves the secp256k1 secret key used for transaction I/O.
    fn get_tx_io_sk(&self) -> secp256k1::SecretKey;

    /// Retrieves the secp256k1 public key corresponding to the transaction I/O secret key.
    fn get_tx_io_pk(&self) -> secp256k1::PublicKey;

    /// Retrieves the Schnorrkel keypair used for generating randomness.
    fn get_rng_keypair(&self) -> schnorrkel::keys::Keypair;

    /// Retrieves the AES-256-GCM encryption key used for snapshot encryption.
    fn get_snapshot_key(&self) -> aes_gcm::Key<aes_gcm::Aes256Gcm>;
}
