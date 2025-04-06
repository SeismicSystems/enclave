//! This module provides the JSON-RPC traits for the enclave server and client.
//! Defines how server's are expected to be built and the shared API

use anyhow::Result;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use jsonrpsee::Methods;
use seismic_enclave_derive::derive_sync_client_trait;
use std::net::SocketAddr;

use crate::auth::JwtSecret;
use crate::auth::{AuthLayer, JwtAuthValidator};
use crate::boot::{
    RetrieveMasterKeyRequest, RetrieveMasterKeyResponse, ShareMasterKeyRequest,
    ShareMasterKeyResponse,
};
use crate::coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse};
use crate::coco_as::{AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse};
use crate::genesis::GenesisDataResponse;
use crate::signing::{
    Secp256k1SignRequest, Secp256k1SignResponse, Secp256k1VerifyRequest, Secp256k1VerifyResponse,
};
use crate::tx_io::{
    IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse,
};

/// A trait for building a server.
pub trait BuildableServer {
    fn addr(&self) -> SocketAddr;
    fn methods(self) -> Methods;
    fn auth_secret(&self) -> JwtSecret;
    async fn start(self) -> Result<ServerHandle>;
    async fn start_rpc_server(self) -> Result<ServerHandle>
    where
        Self: Sized,
    {
        let addr = self.addr();
        let secret = self.auth_secret();
        let http_middleware =
            tower::ServiceBuilder::new().layer(AuthLayer::new(JwtAuthValidator::new(secret)));
        let rpc_server = ServerBuilder::new()
            .set_http_middleware(http_middleware)
            .build(addr)
            .await?;
        let module = self.methods();

        let server_handle = rpc_server.start(module);
        Ok(server_handle)
    }
}

/// The JSON-RPC trait for the enclave server and client, defining the API.
#[derive_sync_client_trait] // derive the SyncEnclaveApi trait, which allows for sync calls, which seismic-reth requires
#[rpc(client, server)] // derive the EnclaveApiClient and EnclaveApiServer traits
pub trait EnclaveApi {
    /// Health check endpoint that returns "OK" if service is running
    #[method(name = "healthCheck")]
    async fn health_check(&self) -> RpcResult<String>;

    /// Get the secp256k1 public key
    #[method(name = "getPublicKey")]
    async fn get_public_key(&self) -> RpcResult<secp256k1::PublicKey>;

    /// Retrieves genesis configuration data for blockchain initialization
    #[method(name = "getGenesisData")]
    async fn get_genesis_data(&self) -> RpcResult<GenesisDataResponse>;

    /// Signs a message using secp256k1 private key
    #[method(name = "sign")]
    async fn sign(&self, _req: Secp256k1SignRequest) -> RpcResult<Secp256k1SignResponse>;

    /// Verifies a secp256k1 signature against a message
    #[method(name = "verify")]
    async fn verify(&self, _req: Secp256k1VerifyRequest) -> RpcResult<Secp256k1VerifyResponse>;

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

    /// Encrypts transaction data using ECDH and AES
    #[method(name = "encrypt")]
    async fn encrypt(&self, _req: IoEncryptionRequest) -> RpcResult<IoEncryptionResponse>;

    /// Decrypts transaction data using ECDH and AES
    #[method(name = "decrypt")]
    async fn decrypt(&self, _req: IoDecryptionRequest) -> RpcResult<IoDecryptionResponse>;

    /// Generates an ephemeral keypair
    #[method(name = "eph_rng.get_keypair")]
    async fn get_eph_rng_keypair(&self) -> RpcResult<schnorrkel::keys::Keypair>;

    /// Retrieves the root key from an existing node
    #[method(name = "boot.retrieve_root_key")]
    async fn boot_retrieve_root_key(
        &self,
        _req: RetrieveMasterKeyRequest,
    ) -> RpcResult<RetrieveMasterKeyResponse>;

    /// Shares the root key with an existing node
    #[method(name = "boot.share_root_key")]
    async fn boot_share_root_key(
        &self,
        _req: ShareMasterKeyRequest,
    ) -> RpcResult<ShareMasterKeyResponse>;

    /// Genesis boot
    #[method(name = "boot.genesis_boot")]
    async fn boot_genesis(&self) -> RpcResult<()>;

    /// Completes the genesis boot
    #[method(name = "boot.complete_boot")]
    async fn complete_boot(&self) -> RpcResult<()>;
}
