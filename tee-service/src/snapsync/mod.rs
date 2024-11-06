use openssl::{pkey::Public, rsa::Rsa};
use tee_service_api::snapsync::SnapSyncResponse;

pub mod handlers;

const DB_PATH: &str = "./src/snapsync.db";

/// Gathers the snapsync data, signs it, and returns a SnapSyncResponse
/// Currently the snapsync data has the io private key and an encrypted version of the state
fn build_snapsync_response(rsa: Rsa<Public>) -> SnapSyncResponse {
    let attestation = attest_to_signing_key();
    let snapsync_data = gather_snapsync_data();
    let signature = sign_snapsync_data();
    SnapSyncResponse {
        server_attestation: attestation,
        snapsync_data,
        signature,
    }
}
