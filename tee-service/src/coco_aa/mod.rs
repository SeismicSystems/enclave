pub mod handlers;

use crate::ATTESTATION_AGENT;
use attestation_agent::AttestationAPIs;

use anyhow::{anyhow, Result};

pub async fn attest(runtime_data: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let coco_aa = ATTESTATION_AGENT.get().unwrap();
    let evidence = coco_aa
        .get_evidence(runtime_data)
        .await
        .map_err(|e| anyhow!("Error while getting evidence: {:?}", e))?;

    Ok(evidence)
}
