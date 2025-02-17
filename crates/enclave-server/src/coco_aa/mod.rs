pub mod handlers;

use crate::ATTESTATION_AGENT;
use attestation_agent::AttestationAPIs;
use attestation_agent::AttestationAgent;

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

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

pub async fn attest(runtime_data: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let coco_aa = ATTESTATION_AGENT.get().unwrap();
    let evidence = coco_aa
        .get_evidence(runtime_data)
        .await
        .map_err(|e| anyhow!("Error while getting evidence: {:?}", e))?;

    Ok(evidence)
}

/// Makes an attestation with a hash of a Secp256k1 public key as the runtime data
/// returns (attestation, signing_pk)
///
/// UNSAFE: Currently this is using a sample key for testing purposes
pub async fn attest_signing_pk() -> Result<(Vec<u8>, secp256k1::PublicKey), anyhow::Error> {
    let signing_pk = seismic_enclave::get_sample_secp256k1_pk();
    let signing_pk_bytes = signing_pk.serialize();
    let pk_hash: [u8; 32] = Sha256::digest(signing_pk_bytes.as_slice()).into();

    let att = attest(pk_hash.as_slice()).await?;

    Ok((att, signing_pk))
}
