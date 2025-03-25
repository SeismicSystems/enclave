pub mod handlers;

use crate::coco_aa::ATTESTATION_AGENT;
use seismic_enclave::request_types::genesis::*;

use attestation_agent::AttestationAPIs;
use sha2::{Digest, Sha256};

async fn att_genesis_data(
    io_pk: secp256k1::PublicKey,
) -> Result<(GenesisData, Vec<u8>), anyhow::Error> {
    // For now the genesis data is just the public key of the IO encryption keypair
    // But this is expected to change in the future
    let genesis_data = GenesisData { io_pk };

    // hash the genesis data and attest to it
    let genesis_data_bytes = genesis_data.to_bytes()?;
    let hash_bytes: [u8; 32] = Sha256::digest(genesis_data_bytes).into();

    // Get the evidence from the attestation agent
    let aa_clone = ATTESTATION_AGENT.clone();
    let coco_aa = aa_clone.get().unwrap();
    let evidence = coco_aa
        .get_evidence(&hash_bytes)
        .await
        .map_err(|e| format!("Error while getting evidence: {:?}", e))
        .unwrap();

    Ok((genesis_data, evidence))
}
