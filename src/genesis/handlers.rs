use attestation_agent::AttestationAPIs;
use hyper::{Body, Request, Response};
use std::convert::Infallible;
use sha2::{Digest, Sha256};

use super::structs::*;
use crate::ATTESTATION_AGENT;
use crate::utils::crypto_utils::get_sample_secp256k1_pk;

/// Handles request to get genesis data.
/// 
/// At genesis the network generates network wide constants, such as the transaction encryption keypair
/// This function returns the genesis data to the client
/// Along with an attestation of such data that can be verified with the attestation/as/eval_evidence endpoint
/// 
/// Currently uses hardcoded values for testing purposes, which will be updated later
pub async fn genesis_get_data_handler(
    _: Request<Body>,
) -> Result<Response<Body>, Infallible> {

    // For now, we load the keypair from a file
    let io_pk = get_sample_secp256k1_pk();

    // For now the genesis data is just the public key of the IO encryption keypair
    // But this is expected to change in the future
    let genesis_data = GenesisData { io_pk };

    // hash the genesis data and attest to it
    let genesis_data_bytes = genesis_data.to_bytes();
    let hash_bytes: [u8; 32] = Sha256::digest(genesis_data_bytes).into();

    // Get the evidence from the attestation agent
    let coco_aa = ATTESTATION_AGENT.get().unwrap();
    let evidence = coco_aa
        .get_evidence(&hash_bytes)
        .await
        .map_err(|e| format!("Error while getting evidence: {:?}", e))
        .unwrap();

    // Return the evidence as a response
    let response_body = GenesisDataResponse { data: genesis_data, evidence };
    let response_json = serde_json::to_string(&response_body).unwrap();
    Ok(Response::new(Body::from(response_json)))
}