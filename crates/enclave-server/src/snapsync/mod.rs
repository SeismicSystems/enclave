pub mod handlers;
pub mod reth_supervisor;
mod snapshot;
mod check_operator;

use crate::coco_aa::attest_signing_pk;
use crate::signing::enclave_sign;
use crate::{get_secp256k1_sk, get_snapshot_key};
use reth_supervisor::{start_reth, stop_reth};
use snapshot::{compress_db, decompress_db, encrypt_snapshot, decrypt_snapshot};
use seismic_enclave::ecdh_encrypt;
use seismic_enclave::request_types::snapsync::{SnapSyncData, SnapSyncResponse};

use secp256k1::rand::rngs::OsRng;
use secp256k1::rand::RngCore;

// pub const RETH_DB_DIR: &str = "/home/azureuser/.local/share/reth/5124/db"; // correct when running reth with `cargo run`
pub const RETH_DB_DIR: &str = "/home/azureuser/.reth/db"; // correct when running reth with supervisorctl
pub const SNAPSHOT_FILE: &str = "seismic_reth_snapshot.tar.lz4";
pub const MDBX_FILE: &str = "mdbx.dat";

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
/// TODO: get real private state data from [location TBD]
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



fn create_encrypted_snapshot(db_dir: &str, snapshot_file: &str, mdbx_file: &str) -> Result<(), anyhow::Error> {
    stop_reth().expect("Failed to stop reth during create_encrypted_snapshot");
    compress_db(db_dir, snapshot_file, mdbx_file)?;
    encrypt_snapshot(db_dir, snapshot_file)?;
    start_reth().expect("Failed to start reth during create_encrypted_snapshot");
    Ok(())
}

fn restore_from_encrypted_snapshot(db_dir: &str, snapshot_file: &str) -> Result<(), anyhow::Error> {
    stop_reth()?;
    decrypt_snapshot(db_dir, snapshot_file)?;
    decompress_db(db_dir, snapshot_file)?;
    start_reth()?;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use reth_supervisor::reth_is_running;

    use std::path::Path;
   
    #[test]
    fn test_create_encrypted_snapshot() {
        assert!(Path::new(format!("{}/{}", RETH_DB_DIR, MDBX_FILE).as_str()).exists());
        assert!(!Path::new(format!("{}/{}.enc", RETH_DB_DIR, SNAPSHOT_FILE).as_str()).exists());
        assert!(reth_is_running()); // assumes reth is running when the test starts

        create_encrypted_snapshot(RETH_DB_DIR, SNAPSHOT_FILE, MDBX_FILE).unwrap();
        assert!(Path::new(format!("{}/{}.enc", RETH_DB_DIR, SNAPSHOT_FILE).as_str()).exists());
        assert!(reth_is_running());
    }

    #[test]
    fn test_restore_from_encrypted_snapshot() {
        assert!(!Path::new(format!("{}/{}", RETH_DB_DIR, MDBX_FILE).as_str()).exists());
        assert!(Path::new(format!("{}/{}.enc", RETH_DB_DIR, SNAPSHOT_FILE).as_str()).exists());
        assert!(reth_is_running()); // assumes reth is running when the test starts

        restore_from_encrypted_snapshot(RETH_DB_DIR, format!("{}.enc", SNAPSHOT_FILE).as_str()).unwrap();
        assert!(Path::new(format!("{}/{}", RETH_DB_DIR, MDBX_FILE).as_str()).exists());
        assert!(reth_is_running());
    }
}