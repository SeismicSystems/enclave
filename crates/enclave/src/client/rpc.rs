// JSON-RPC Trait for Server and Client
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;

use crate::coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse};
use crate::coco_as::{AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse};
use crate::genesis::GenesisDataResponse;
use crate::get_sample_schnorrkel_keypair;
use crate::signing::{
    Secp256k1SignRequest, Secp256k1SignResponse, Secp256k1VerifyRequest, Secp256k1VerifyResponse,
};
use crate::snapsync::{SnapSyncRequest, SnapSyncResponse};
use crate::tx_io::{
    IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse,
};
#[rpc(client, server)]
pub trait EnclaveApi {
    /// Health check endpoint that returns "OK" if service is running
    #[method(name = "health.check")]
    async fn health_check(&self) -> RpcResult<String>;

    /// Retrieves genesis configuration data for blockchain initialization
    #[method(name = "genesis.get_data")]
    async fn genesis_get_data(&self) -> RpcResult<GenesisDataResponse>;

    /// Provides backup data for snapshot synchronization
    #[method(name = "snapsync.provide_backup")]
    async fn provide_snapsync_backup(
        &self,
        request: SnapSyncRequest,
    ) -> RpcResult<SnapSyncResponse>;

    /// Signs a message using secp256k1 private key
    #[method(name = "signing.sign")]
    async fn secp256k1_sign(&self, req: Secp256k1SignRequest) -> RpcResult<Secp256k1SignResponse>;

    /// Verifies a secp256k1 signature against a message
    #[method(name = "signing.verify")]
    async fn secp256k1_verify(
        &self,
        req: Secp256k1VerifyRequest,
    ) -> RpcResult<Secp256k1VerifyResponse>;

    /// Generates attestation evidence from the attestation authority
    #[method(name = "attestation.aa.get_evidence")]
    async fn attestation_get_evidence(
        &self,
        req: AttestationGetEvidenceRequest,
    ) -> RpcResult<AttestationGetEvidenceResponse>;

    /// Evaluates provided attestation evidence
    #[method(name = "attestation.as.eval_evidence")]
    async fn attestation_eval_evidence(
        &self,
        req: AttestationEvalEvidenceRequest,
    ) -> RpcResult<AttestationEvalEvidenceResponse>;

    /// Encrypts transaction data using ECDH and AES
    #[method(name = "tx_io.encrypt")]
    async fn tx_io_encrypt(&self, req: IoEncryptionRequest) -> RpcResult<IoEncryptionResponse>;

    /// Decrypts transaction data using ECDH and AES
    #[method(name = "tx_io.decrypt")]
    async fn tx_io_decrypt(&self, req: IoDecryptionRequest) -> RpcResult<IoDecryptionResponse>;

    /// Generates an ephemeral keypair
    #[method(name = "eph_rng.get_keypair")]
    async fn get_eph_rng_keypair(&self) -> RpcResult<schnorrkel::keys::Keypair> {
        Ok(get_sample_schnorrkel_keypair())
    }
}
