pub mod handlers;

const DB_PATH: &str = "./src/snapsync.db";



// fn build_snapsync_response() -> SnapSyncResponse {
//     let attestation = attest_to_signing_key();
//     let snapsync_data = gather_snapsync_data();
//     let signature = sign_snapsync_data();
//     SnapSyncResponse {
//         server_attestation: attestation,
//         snapsync_data,
//         signature,
//     }
// }