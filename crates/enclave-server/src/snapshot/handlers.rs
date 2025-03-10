use super::{MDBX_FILE, RETH_DB_DIR, SNAPSHOT_FILE};
use seismic_enclave::{
    rpc_bad_argument_error, rpc_internal_server_error, rpc_missing_snapshot_error,
    snapshot::{
        DownloadEncryptedSnapshotRequest, DownloadEncryptedSnapshotResponse,
        PrepareEncryptedSnapshotRequest, PrepareEncryptedSnapshotResponse,
        RestoreFromEncryptedSnapshotRequest, RestoreFromEncryptedSnapshotResponse,
        UploadEncryptedSnapshotRequest, UploadEncryptedSnapshotResponse,
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

// Gives the client the encrypted snapshot
// Assumes the snapshot is already created
pub async fn download_encrypted_snapshot_handler(
    _request: DownloadEncryptedSnapshotRequest,
) -> RpcResult<DownloadEncryptedSnapshotResponse> {
    let encrypted_snapshot_path = format!("{}/{}.enc", RETH_DB_DIR, SNAPSHOT_FILE);
    if !Path::new(&encrypted_snapshot_path).exists() {
        return Err(rpc_missing_snapshot_error());
    }
    let encrypted_snapshot = match fs::read(&encrypted_snapshot_path) {
        Ok(bytes) => {
            general_purpose::STANDARD.encode(bytes) // encode file as a string
        }
        Err(e) => return Err(rpc_internal_server_error(e.into())),
    };
    let resp = DownloadEncryptedSnapshotResponse {
        encrypted_snapshot: encrypted_snapshot.into(),
    };
    Ok(resp)
}

// Uploads the encrypted snapshot to the enclave server
// File gets put the in the correct spot
pub async fn upload_encrypted_snapshot_handler(
    request: UploadEncryptedSnapshotRequest,
) -> RpcResult<UploadEncryptedSnapshotResponse> {
    let encrypted_snapshot_path = format!("{}/{}.enc", RETH_DB_DIR, SNAPSHOT_FILE);
    let encrypted_snapshot_bytes = general_purpose::STANDARD
        .decode(request.encrypted_snapshot)
        .map_err(|e| rpc_bad_argument_error(e.into()))?;
    fs::write(encrypted_snapshot_path, encrypted_snapshot_bytes)
        .map_err(|e| rpc_internal_server_error(e.into()))?;
    let resp = UploadEncryptedSnapshotResponse { success: true };
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
