
/// JSON-RPC Trait for Server and Client
use anyhow::Result;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use seismic_enclave_derive::derive_sync_client_trait;

use crate::tx_io::{IoDecryptionRequest, IoDecryptionResponse};

#[derive_sync_client_trait] // get SyncEnclaveApi trait
#[rpc(client, server)] // get EnclaveApiClient EnclaveApiServer trait
pub trait EnclaveInternalAPI {
    /// Decrypts transaction data using ECDH and AES
    #[method(name = "decrypt")]
    async fn decrypt(&self, _req: IoDecryptionRequest) -> RpcResult<IoDecryptionResponse>;
}
