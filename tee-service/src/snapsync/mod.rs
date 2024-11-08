use tee_service_api::request_types::snapsync::{SnapSyncData, SnapSyncResponse};
use crate::{coco_aa::attest_signing_pk, tx_io::enclave_ecdh_encrypt};
use crate::signing::enclave_sign;

pub mod handlers;

const DB_PATH: &str = "./src/snapsync.db";

/// Gathers the snapsync data, signs it, and returns a SnapSyncResponse
/// Currently the snapsync data has the io private key and an encrypted version of the state
pub async fn build_snapsync_response(client_signing_pk: secp256k1::PublicKey) -> Result<SnapSyncResponse, anyhow::Error> {
    // Make an attestation with the signing key
    let (attestation, server_signing_pk) = attest_signing_pk().await?;
    let server_signing_pk_bytes = server_signing_pk.serialize().to_vec();
    
    // Gather the snapsync data
    let snapsync_data: SnapSyncData = gather_snapsync_data().await?;
    let snapsync_bytes = snapsync_data.to_bytes();

    // encrypt the snapsync data
    let nonce = 65; // TODO: get a nonce more securely. Choose randomly?
    let encrypted_data = enclave_ecdh_encrypt(
        &client_signing_pk, 
        snapsync_bytes, 
        nonce,
    )?;

    // Sign the snapsync data
    let signature = enclave_sign(&encrypted_data)?;

    Ok(SnapSyncResponse {
        server_attestation: attestation,
        server_signing_pk: server_signing_pk_bytes,
        encrypted_data,
        nonce,
        signature,
    })
}

/// Gathers the snapsync data
/// Currently the snapsync data has the io private key and the private state
/// 
/// TODO: get real private state data from [location TBD]
async fn gather_snapsync_data() -> Result<SnapSyncData, anyhow::Error> {
    let sample_private_state = format!("private state @ %{}", DB_PATH).as_bytes().to_vec();
    Ok(SnapSyncData {
        io_sk: "io sk".as_bytes().to_vec(),
        state: sample_private_state,
    })
}
