//! JSON-RPC Trait for Server and Client

use anyhow::Result;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use jsonrpsee::Methods;
use seismic_enclave_derive::derive_sync_client_trait;
use std::fmt::Debug;
use tracing::info;
use std::net::SocketAddr;

use crate::coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse};
use crate::coco_as::{AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse};
use crate::genesis::GenesisDataResponse;
use crate::signing::{
    Secp256k1SignRequest, Secp256k1SignResponse, Secp256k1VerifyRequest, Secp256k1VerifyResponse,
};
use crate::snapshot::{
    PrepareEncryptedSnapshotRequest, PrepareEncryptedSnapshotResponse,
    RestoreFromEncryptedSnapshotRequest, RestoreFromEncryptedSnapshotResponse,
};
use crate::snapsync::{SnapSyncRequest, SnapSyncResponse};
use crate::tx_io::{
    IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse,
};

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
        info!(target: "rpc::enclave", "Server started at {}", addr);
        Ok(server_handle)
    }
}


pub trait SyncEnclaveApiClientBuilder: Clone + Debug + Send + Sync + Unpin {
    type Client: SyncEnclaveApiClient + Clone + Debug + Send + Sync + Unpin;
    fn build(self) -> Self::Client;
}

#[derive_sync_client_trait] // get SyncEnclaveApi trait
#[rpc(client, server)] // get EnclaveApiClient EnclaveApiServer trait
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

    /// Provides backup data for snapshot synchronization
    #[method(name = "getSnapsyncBackup")]
    async fn get_snapsync_backup(&self, _req: SnapSyncRequest) -> RpcResult<SnapSyncResponse>;

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
}
