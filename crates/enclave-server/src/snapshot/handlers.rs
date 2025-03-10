use super::{MDBX_FILE, RETH_DB_DIR, SNAPSHOT_FILE};
use seismic_enclave::{
    rpc_bad_argument_error, rpc_internal_server_error, rpc_missing_snapshot_error,
    snapshot::{
        // DownloadEncryptedSnapshotRequest, DownloadEncryptedSnapshotResponse,
        PrepareEncryptedSnapshotRequest, PrepareEncryptedSnapshotResponse,
        RestoreFromEncryptedSnapshotRequest, RestoreFromEncryptedSnapshotResponse,
        // UploadEncryptedSnapshotRequest, UploadEncryptedSnapshotResponse,
    },
};

use base64::{engine::general_purpose, Engine as _};
use jsonrpsee::core::RpcResult;
use std::{fs, path::Path};

// Prepares an encrypted snapshot of the reth database
// the snapshot is compressed and encrypted with the snapshot key
pub async fn prepare_encrypted_snapshot_handler(
    _request: PrepareEncryptedSnapshotRequest,
) -> RpcResult<PrepareEncryptedSnapshotResponse> {
    let res = super::prepare_encrypted_snapshot(RETH_DB_DIR, SNAPSHOT_FILE, MDBX_FILE);
    let resp = PrepareEncryptedSnapshotResponse {
        success: res.is_ok(),
    };
    Ok(resp)
}

// Restores the reth database from the encrypted snapshot
// stops reth, decryptes and decompresses the snapshot, restarts reth with snapshot data active
pub async fn restore_from_encrypted_snapshot_handler(
    _request: RestoreFromEncryptedSnapshotRequest,
) -> RpcResult<RestoreFromEncryptedSnapshotResponse> {
    let encrypted_snapshot_path = format!("{}/{}.enc", RETH_DB_DIR, SNAPSHOT_FILE);
    if !Path::new(&encrypted_snapshot_path).exists() {
        return Err(rpc_missing_snapshot_error());
    }
    let res = super::restore_from_encrypted_snapshot(RETH_DB_DIR, SNAPSHOT_FILE);
    let resp = RestoreFromEncryptedSnapshotResponse {
        success: res.is_ok(),
    }; // TODO: consider adding a blocknumber to the response
    Ok(resp)
}
