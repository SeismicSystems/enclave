pub mod handlers;

use crate::coco_aa::attest_signing_pk;
use crate::signing::enclave_sign;
use crate::{get_secp256k1_sk, get_snapshot_key};
use seismic_enclave::ecdh_encrypt;
use seismic_enclave::request_types::snapsync::{SnapSyncData, SnapSyncResponse};

use secp256k1::rand::rngs::OsRng;
use secp256k1::rand::RngCore;

pub const RETH_DB_DIR: &str = "/home/azureuser/.reth/db";

/// Gathers the snapsync data, signs it, and returns a SnapSyncResponse
/// Currently the snapsync data has the io private key and an encrypted version of the state
pub async fn build_snapsync_response(
    client_signing_pk: secp256k1::PublicKey,
) -> Result<SnapSyncResponse, anyhow::Error> {
    // Make an attestation with the signing key
    let (attestation, server_signing_pk) = attest_signing_pk().await?;
    let server_signing_pk_bytes = server_signing_pk.serialize().to_vec();

    // Gather the snapsync data
    let snapsync_data: SnapSyncData = gather_snapsync_data()?;
    let snapsync_bytes = snapsync_data.to_bytes()?;

    // generate a random nonce
    // TODO: evaluate security of this approach
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    // encrypt the snapsync data
    let encrypted_data = ecdh_encrypt(
        &client_signing_pk,
        &get_secp256k1_sk(),
        snapsync_bytes,
        nonce,
    )?;

    // Sign the snapsync data
    let signature = enclave_sign(&encrypted_data)?;

    Ok(SnapSyncResponse {
        server_attestation: attestation,
        server_signing_pk: server_signing_pk_bytes,
        encrypted_data,
        nonce: nonce.to_vec(),
        signature,
    })
}

/// Gathers the snapsync data
/// Currently the snapsync data has the io private key and the private state
///
/// TODO: Update this to have real private keys, no state (now handled by snapshot)
fn gather_snapsync_data() -> Result<SnapSyncData, anyhow::Error> {
    let sample_private_state = format!("private state @ %{}", RETH_DB_DIR)
        .as_bytes()
        .to_vec();
    let snapshot_sk = get_snapshot_key();
    Ok(SnapSyncData {
        io_sk: snapshot_sk.to_vec(),
        state: sample_private_state,
    })
}
