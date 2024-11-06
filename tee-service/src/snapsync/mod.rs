use openssl::{pkey::Public, rsa::Rsa};
use tee_service_api::{get_sample_secp256k1_sk, snapsync::{SnapSyncData, SnapSyncResponse}};
use crate::coco_aa::attest_signing_pk;
use tee_service_api::secp256k1_sign_digest;
use tee_service_api::rsa_encrypt;

pub mod handlers;

const DB_PATH: &str = "./src/snapsync.db";

/// Gathers the snapsync data, signs it, and returns a SnapSyncResponse
/// Currently the snapsync data has the io private key and an encrypted version of the state
pub async fn build_snapsync_response(rsa: Rsa<Public>) -> Result<SnapSyncResponse, anyhow::Error> {
    // Make an attestation with the signing key
    let (attestation, signing_pk) = attest_signing_pk().await?;
    let server_signing_pk = signing_pk.serialize().to_vec();
    
    // Gather the snapsync data
    let snapsync_data: SnapSyncData = gather_snapsync_data().await?;
    let snapsync_bytes = snapsync_data.to_bytes();

    // encrypt the snapsync data
    let rsa_pk_pem = rsa.public_key_to_pem().unwrap();
    let encrypted_data = rsa_encrypt(snapsync_bytes.as_slice(), rsa_pk_pem.as_slice())?;

    // Sign the snapsync data
    let signing_sk = get_sample_secp256k1_sk();
    let signature = secp256k1_sign_digest(&snapsync_bytes, signing_sk)
        .expect("Internal Error while signing the message");

    Ok(SnapSyncResponse {
        server_attestation: attestation,
        server_signing_pk,
        encrypted_data,
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