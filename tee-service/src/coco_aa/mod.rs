pub mod handlers;

use crate::ATTESTATION_AGENT;
use attestation_agent::AttestationAPIs;

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

pub async fn attest(runtime_data: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let coco_aa = ATTESTATION_AGENT.get().unwrap();
    let evidence = coco_aa
        .get_evidence(runtime_data)
        .await
        .map_err(|e| anyhow!("Error while getting evidence: {:?}", e))?;

    Ok(evidence)
}

/// Makes an attestation with a hash of a rsa public key as the runtime data
/// returns (attestation, public key pem)
/// 
/// UNSAFE: Currently this is using a sample key for testing purposes
pub async fn attest_signing_key() -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
    let rsa = tee_service_api::get_sample_rsa();
    let public_key_pem = rsa.public_key_to_pem().unwrap();
    let pk_hash: [u8; 32] = Sha256::digest(public_key_pem.as_slice()).into();

    let att = attest(pk_hash.as_slice()).await?;

    Ok((att, public_key_pem))
}
