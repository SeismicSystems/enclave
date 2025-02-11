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
use attestation_service::config::Config;
use attestation_service::AttestationService;
use base64::Engine;
use coco_as::policies;
use once_cell::sync::OnceCell;
use std::sync::Arc;
use tokio::sync::RwLock;

use seismic_enclave::{get_sample_secp256k1_pk, get_sample_secp256k1_sk};

pub static ATTESTATION_SERVICE: OnceCell<Arc<RwLock<AttestationService>>> = OnceCell::new();
pub static ATTESTATION_AGENT: OnceCell<Arc<AttestationAgent>> = OnceCell::new();

// initializes the AttestationAgent
// which is reponsible for generating attestations
pub fn init_coco_aa() -> Result<()> {
    // Check if the service is already initialized
    // This helps with multithreaded testing
    if ATTESTATION_AGENT.get().is_some() {
        // AttestationAgent is already initialized, so we skip re-initialization.
        return Ok(());
    }

    let config_path = None;
    let coco_aa = AttestationAgent::new(config_path).expect("Failed to create an AttestationAgent");
    ATTESTATION_AGENT
        .set(Arc::new(coco_aa))
        .map_err(|_| anyhow::anyhow!("Failed to set AttestationAgent"))?;

    Ok(())
}

// initializes the AttestationService
// which is reponsible for evaluating attestations
pub async fn init_coco_as(config: Option<Config>) -> Result<()> {
    // Check if the service is already initialized
    // This helps with multithreaded testing
    if ATTESTATION_SERVICE.get().is_some() {
        // AttestationService is already initialized, so we skip re-initialization.
        return Ok(());
    }

    let config = config.unwrap_or_default();

    // Initialize the AttestationService
    let coco_as = AttestationService::new(config)
        .await
        .expect("Failed to create an AttestationService");
    let lock = tokio::sync::RwLock::new(coco_as);
    ATTESTATION_SERVICE
        .set(Arc::new(lock))
        .map_err(|_| anyhow::anyhow!("Failed to set AttestationService"))?;

    // initialize the policies
    init_as_policies().await?;
    Ok(())
}

/// Initializes the AS policies from the policies directory
/// While every AS eval request checks that the evidence was created by a real enclave
/// A policy defines the expected values of that enclave.
///
/// For example, the important values for AxTdxVtpm are the MRSEAM and MRTD values,
/// which respectively fingerprint the TDX module and the guest firmware that are running
///
/// TODO: replace policies, particularly the Yocto policy, with finalized policies before mainnet
pub async fn init_as_policies() -> Result<()> {
    let coco_as = ATTESTATION_SERVICE.get().unwrap();
    let mut writeable_as = coco_as.write().await;

    let policies = vec![
        (policies::ALLOW_POLICY.to_string(), "allow".to_string()),
        (policies::DENY_POLICY.to_string(), "deny".to_string()),
        (policies::YOCTO_POLICY.to_string(), "yocto".to_string()),
    ];

    for (policy, policy_id) in policies {
        let policy_encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(policy);
        writeable_as
            .set_policy(policy_id.to_string(), policy_encoded)
            .await?;
    }

    Ok(())
}

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
