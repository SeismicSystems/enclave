use super::{MDBX_FILE, RETH_DB_DIR, SNAPSHOT_FILE, DATA_DISK_DIR};
use seismic_enclave::{
    // rpc_bad_argument_error, rpc_internal_server_error, 
    rpc_missing_snapshot_error,
    snapshot::{
        PrepareEncryptedSnapshotRequest, PrepareEncryptedSnapshotResponse,
        RestoreFromEncryptedSnapshotRequest, RestoreFromEncryptedSnapshotResponse,
    },
};

// use base64::{engine::general_purpose, Engine as _};
use jsonrpsee::core::RpcResult;
// use std::fs;
use std::path::Path;

// Prepares an encrypted snapshot of the reth database
// the snapshot is compressed and encrypted with the snapshot key
// encrypted snapshot should be saved in a detatchable azure data disk, as opposed to the OS disk
pub async fn prepare_encrypted_snapshot_handler(
    _request: PrepareEncryptedSnapshotRequest,
) -> RpcResult<PrepareEncryptedSnapshotResponse> {
    let res = super::prepare_encrypted_snapshot(RETH_DB_DIR, DATA_DISK_DIR, SNAPSHOT_FILE, MDBX_FILE); 
    let resp = PrepareEncryptedSnapshotResponse {
        success: res.is_ok(),
        error: res.err().map(|e| e.to_string()).unwrap_or_default(),
    };
    Ok(resp)
}

// Restores the reth database from the encrypted snapshot
// stops reth, decryptes and decompresses the snapshot, restarts reth with snapshot data active
pub async fn restore_from_encrypted_snapshot_handler(
    _request: RestoreFromEncryptedSnapshotRequest,
) -> RpcResult<RestoreFromEncryptedSnapshotResponse> {
    let encrypted_snapshot_path = format!("{}/{}.enc", DATA_DISK_DIR, SNAPSHOT_FILE);
    if !Path::new(&encrypted_snapshot_path).exists() {
        return Err(rpc_missing_snapshot_error());
    }
    let res = super::restore_from_encrypted_snapshot(RETH_DB_DIR, DATA_DISK_DIR, SNAPSHOT_FILE);
    let resp = RestoreFromEncryptedSnapshotResponse {
        success: res.is_ok(),
        error: res.err().map(|e| e.to_string()).unwrap_or_default(),
        // TODO: consider adding a blocknumber / other fieldsto the response
    }; 
    Ok(resp)
}
