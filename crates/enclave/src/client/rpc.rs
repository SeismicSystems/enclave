//! This module provides the JSON-RPC traits for the enclave server and client.
//! Defines how server's are expected to be built and the shared API

use anyhow::Result;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use jsonrpsee::Methods;
use seismic_enclave_derive::derive_sync_client_trait;
use std::fmt::Debug;
use std::net::SocketAddr;

use crate::request_types::*;

/// A trait for building a server.
pub trait BuildableServer {
    fn addr(&self) -> SocketAddr;
    fn methods(self) -> Methods;
    async fn start(self) -> Result<ServerHandle>;
    async fn start_rpc_server(self) -> Result<ServerHandle>
    where
        Self: Sized,
    {
        let addr = self.addr();
        let rpc_server = ServerBuilder::new().build(addr).await?;
        let module = self.methods();

        let server_handle = rpc_server.start(module);
        Ok(server_handle)
    }
}

pub trait SyncEnclaveApiClientBuilder: Clone + Debug + Send + Sync + Unpin {
    type Client: SyncEnclaveApiClient + Clone + Debug + Send + Sync + Unpin;
    fn build(self) -> Self::Client;
}

/// The JSON-RPC trait for the enclave server and client, defining the API.
#[derive_sync_client_trait] // derive the SyncEnclaveApi trait, which allows for sync calls, which seismic-reth requires
#[rpc(client, server)] // derive the EnclaveApiClient and EnclaveApiServer traits
pub trait EnclaveApi {
    /// Health check endpoint that returns "OK" if service is running
    #[method(name = "healthCheck")]
    async fn health_check(&self) -> RpcResult<String>;

    /// Get the secp256k1 public key
    #[method(name = "getPurposeKeys")]
    async fn get_purpose_keys(
        &self,
        req: GetPurposeKeysRequest,
    ) -> RpcResult<GetPurposeKeysResponse>;

    /// Generates attestation evidence from the attestation authority
    #[method(name = "getAttestationEvidence")]
    async fn get_attestation_evidence(
        &self,
        _req: AttestationGetEvidenceRequest,
    ) -> RpcResult<AttestationGetEvidenceResponse>;

    /// Evaluates provided attestation evidence
    #[method(name = "evalAttestationEvidence")]
    async fn eval_attestation_evidence(
        &self,
        _req: AttestationEvalEvidenceRequest,
    ) -> RpcResult<AttestationEvalEvidenceResponse>;

    /// Retrieves the root key from an existing node
    #[method(name = "boot.retrieve_root_key")]
    async fn boot_retrieve_root_key(
        &self,
        _req: RetrieveRootKeyRequest,
    ) -> RpcResult<RetrieveRootKeyResponse>;

    /// Shares the root key with an existing node
    #[method(name = "boot.share_root_key")]
    async fn boot_share_root_key(
        &self,
        _req: ShareRootKeyRequest,
    ) -> RpcResult<ShareRootKeyResponse>;

    /// Genesis boot
    #[method(name = "boot.genesis_boot")]
    async fn boot_genesis(&self) -> RpcResult<()>;

    /// Completes the genesis boot
    #[method(name = "boot.complete_boot")]
    async fn complete_boot(&self) -> RpcResult<()>;
}
