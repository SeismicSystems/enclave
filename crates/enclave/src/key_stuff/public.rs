/// JSON-RPC Trait for Server and Client
use anyhow::Result;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use seismic_enclave_derive::derive_sync_client_trait;

#[derive_sync_client_trait] // get SyncEnclaveApi trait
#[rpc(client, server)] // get EnclaveApiClient EnclaveApiServer trait
pub trait EnclavePublicAPI {
    /// Health check endpoint that returns "OK" if service is running
    #[method(name = "healthCheck")]
    async fn health_check(&self) -> RpcResult<String>;

    /// Get the secp256k1 public key
    #[method(name = "getPublicKey")]
    async fn get_public_key(&self) -> RpcResult<secp256k1::PublicKey>;
}

