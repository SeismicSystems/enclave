/// JSON-RPC Trait for Server and Client
use anyhow::Result;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use seismic_enclave_derive::derive_sync_client_trait;

use crate::snapshot::{
    PrepareEncryptedSnapshotRequest, PrepareEncryptedSnapshotResponse,
};

#[derive_sync_client_trait] // get SyncEnclaveApi trait
#[rpc(client, server)] // get EnclaveApiClient EnclaveApiServer trait
pub trait EnclaveOperatorAPI {
    #[method(name = "snapshot.prepare_encrypted_snapshot")]
    async fn prepare_encrypted_snapshot(
        &self,
        request: PrepareEncryptedSnapshotRequest,
    ) -> RpcResult<PrepareEncryptedSnapshotResponse>;
}