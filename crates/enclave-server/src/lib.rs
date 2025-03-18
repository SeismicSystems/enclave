mod coco_aa;
mod coco_as;
mod genesis;
pub mod server;
mod signing;
pub mod snapshot; // pub for integration testing
mod snapsync;
mod tx_io;
pub mod utils;
pub mod key_manager;

use seismic_enclave::{
    get_unsecure_sample_aesgcm_key, get_unsecure_sample_schnorrkel_keypair,
    get_unsecure_sample_secp256k1_pk, get_unsecure_sample_secp256k1_sk,
};

/// Loads a secp256k1 private key from a file.
///
/// This function reads the keypair from a JSON file for testing purposes. Eventually, it should
/// be replaced with a more secure solution, such as requesting a key from a KMS service.
///
/// # Returns
/// A secp256k1 `SecretKey` loaded from the keypair file.
///
/// # Panics
/// The function may panic if the file is missing or if it cannot deserialize the keypair.
///
/// # TODO: replace with a more secure solution. Currently loads a hardcoded sample
fn get_secp256k1_sk() -> secp256k1::SecretKey {
    get_unsecure_sample_secp256k1_sk()
}

/// Loads a secp256k1 public key from a file.
///
/// This function reads the keypair from a JSON file for testing purposes. Eventually, it should
/// be replaced with a more secure solution, such as requesting a key from a KMS service.
///
/// # Returns
/// A secp256k1 `PublicKey` loaded from the keypair file.
///
/// # Panics
/// The function may panic if the file is missing or if it cannot deserialize the keypair.
///
/// # TODO: replace with a more secure solution. Currently loads a hardcoded sample
fn get_secp256k1_pk() -> secp256k1::PublicKey {
    get_unsecure_sample_secp256k1_pk()
}

/// Loads a Schnorrkel keypair from a file.
///
/// This function retrieves a keypair from a JSON file for testing purposes. Like `get_secp256k1_pk`,
/// this implementation is insecure and should be replaced with a more secure approach, such as
/// generating the keypair dynamically or obtaining it from a KMS service.
///
/// # Returns
/// A `schnorrkel::keys::Keypair` loaded from the keypair file.
///
/// # Panics
/// This function may panic if the file is missing, corrupted, or cannot be properly deserialized.
///
/// # TODO: Replace this function with a more secure key management solution.
fn get_schnorrkel_keypair() -> schnorrkel::keys::Keypair {
    get_unsecure_sample_schnorrkel_keypair()
}

/// Generates an AES-GCM encryption key for snapshot encryption.
///
/// This function retrieves a predefined, insecure AES-256-GCM key for testing purposes.
/// this implementation is insecure and should be replaced with a more secure approach, such as
/// generating the keypair dynamically or obtaining it from a KMS service.
///
/// # Returns
/// An `aes_gcm::Key<aes_gcm::Aes256Gcm>` instance representing the encryption key.
///
/// # Panics
/// This function may panic if the underlying key retrieval mechanism fails.
///
/// # TODO: Replace this function with a more secure key management solution.
fn get_snapshot_key() -> aes_gcm::Key<aes_gcm::Aes256Gcm> {
    get_unsecure_sample_aesgcm_key()
}
