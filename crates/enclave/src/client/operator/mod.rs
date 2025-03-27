/// JSON-RPC Trait for Server and Client
use anyhow::Result;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use seismic_enclave_derive::derive_sync_client_trait;

use crate::genesis::GenesisDataResponse;
use crate::snapshot::{
    PrepareEncryptedSnapshotRequest, PrepareEncryptedSnapshotResponse,
    RestoreFromEncryptedSnapshotRequest, RestoreFromEncryptedSnapshotResponse,
};
use crate::snapsync::{SnapSyncRequest, SnapSyncResponse};

#[derive_sync_client_trait] // get SyncEnclaveApi trait
#[rpc(client, server)] // get EnclaveApiClient EnclaveApiServer trait
pub trait EnclaveOperatorAPI {
    #[method(name = "snapshot.prepare_encrypted_snapshot")]
    async fn prepare_encrypted_snapshot(
        &self,
        request: PrepareEncryptedSnapshotRequest,
    ) -> RpcResult<PrepareEncryptedSnapshotResponse>;

    #[method(name = "snapshot.restore_from_encrypted_snapshot")]
    async fn restore_from_encrypted_snapshot(
        &self,
        request: RestoreFromEncryptedSnapshotRequest,
    ) -> RpcResult<RestoreFromEncryptedSnapshotResponse>;

    /// Retrieves genesis configuration data for blockchain initialization
    #[method(name = "getGenesisData")]
    async fn get_genesis_data(&self) -> RpcResult<GenesisDataResponse>;

    /// Provides backup data for snapshot synchronization
    #[method(name = "getSnapsyncBackup")]
    async fn get_snapsync_backup(&self, _req: SnapSyncRequest) -> RpcResult<SnapSyncResponse>;
}
