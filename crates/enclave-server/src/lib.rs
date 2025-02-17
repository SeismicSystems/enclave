mod coco_aa;
mod coco_as;
mod genesis;
pub mod server;
mod signing;
mod snapsync;
mod tx_io;
mod utils;

use anyhow::Result;
use attestation_agent::AttestationAgent;
use attestation_service::{config::Config, AttestationService};
use base64::Engine;
use coco_as::policies;
use once_cell::sync::OnceCell;
use std::sync::Arc;
use tokio::sync::RwLock;

use attestation_service::token::simple;
use attestation_service::token::AttestationTokenConfig;

use seismic_enclave::{get_sample_secp256k1_pk, get_sample_secp256k1_sk};

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
    get_sample_secp256k1_sk()
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
    get_sample_secp256k1_pk()
}
