/// JSON-RPC Trait for Server and Client
use anyhow::Result;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use seismic_enclave_derive::derive_sync_client_trait;

use crate::coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse};
use crate::coco_as::{AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse};
use crate::signing::{
    Secp256k1SignRequest, Secp256k1SignResponse, Secp256k1VerifyRequest, Secp256k1VerifyResponse,
};
use crate::tx_io::{
    IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse,
};

#[derive_sync_client_trait] // get SyncEnclaveInternalAPIClient trait
#[rpc(client, server)] // get EnclaveInternalAPIClient traits
pub trait EnclaveInternalAPI {
    /// Encrypts transaction data using ECDH and AES
    #[method(name = "encrypt")]
    async fn encrypt(&self, _req: IoEncryptionRequest) -> RpcResult<IoEncryptionResponse>;

    /// Decrypts transaction data using ECDH and AES
    #[method(name = "decrypt")]
    async fn decrypt(&self, _req: IoDecryptionRequest) -> RpcResult<IoDecryptionResponse>;

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

    /// Generates an ephemeral keypair
    #[method(name = "eph_rng.get_keypair")]
    async fn get_eph_rng_keypair(&self) -> RpcResult<schnorrkel::keys::Keypair>;
}
