use super::{DATA_DISK_DIR, RETH_DATA_DIR, SNAPSHOT_DIR, SNAPSHOT_FILE};
use seismic_enclave::{
    rpc_missing_snapshot_error,
    snapshot::{
        PrepareEncryptedSnapshotRequest, PrepareEncryptedSnapshotResponse,
        RestoreFromEncryptedSnapshotRequest, RestoreFromEncryptedSnapshotResponse,
    },
};

use jsonrpsee::core::RpcResult;
use std::path::Path;

/// Prepares an encrypted snapshot of the Reth database for backup or migration.
///
/// This handler compresses the contents of the Reth database directory and encrypts
/// the resulting snapshot archive using a predefined snapshot key. The encrypted
/// snapshot is stored on a detachable Azure data disk (rather than
/// the OS disk) for improved portability and separation from runtime state.
///
/// # Arguments
///
/// * `_request` - RPC request payload (currently unused, but included for maintainability).
///
/// # Returns
///
/// Returns a [`PrepareEncryptedSnapshotResponse`] containing a `success` flag and an optional `error` string.
pub async fn prepare_encrypted_snapshot_handler(
    _request: PrepareEncryptedSnapshotRequest,
) -> RpcResult<PrepareEncryptedSnapshotResponse> {
    let res = super::prepare_encrypted_snapshot(
        RETH_DATA_DIR,
        DATA_DISK_DIR,
        SNAPSHOT_DIR,
        SNAPSHOT_FILE,
    );
    let resp = PrepareEncryptedSnapshotResponse {
        success: res.is_ok(),
        error: res.err().map(|e| e.to_string()).unwrap_or_default(),
    };
    Ok(resp)
}

/// Restores the Reth database from an encrypted snapshot archive.
///
/// This handler stops the Reth node, decrypts and decompresses the snapshot file,
/// and replaces the active data directory with the restored snapshot contents,
/// and restarts reth using the restored state. The snapshot archive is expected to
/// be located on a detachable Azure data disk (rather than the OS disk) that
/// must be mounted at `DATA_DISK_DIR` before restoration.
///
/// # Arguments
///
/// * `_request` - RPC request payload (currently unused, included for maintainability).
///
/// # Returns
///
/// Returns a [`RestoreFromEncryptedSnapshotResponse`] containing a `success` flag and an optional `error` string.
pub async fn restore_from_encrypted_snapshot_handler(
    _request: RestoreFromEncryptedSnapshotRequest,
) -> RpcResult<RestoreFromEncryptedSnapshotResponse> {
    let encrypted_snapshot_path = format!("{}/{}.enc", DATA_DISK_DIR, SNAPSHOT_FILE);
    if !Path::new(&encrypted_snapshot_path).exists() {
        return Err(rpc_missing_snapshot_error());
    }
    let res = super::restore_from_encrypted_snapshot(
        RETH_DATA_DIR,
        DATA_DISK_DIR,
        SNAPSHOT_DIR,
        SNAPSHOT_FILE,
    );
    let resp = RestoreFromEncryptedSnapshotResponse {
        success: res.is_ok(),
        error: res.err().map(|e| e.to_string()).unwrap_or_default(),
    };
    Ok(resp)
}
