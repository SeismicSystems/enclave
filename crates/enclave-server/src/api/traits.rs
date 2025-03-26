use jsonrpsee::core::{async_trait, RpcResult};
use anyhow::Result;
use secp256k1::PublicKey;
use seismic_enclave::{coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse}, genesis::GenesisDataResponse, signing::{Secp256k1SignRequest, Secp256k1SignResponse, Secp256k1VerifyRequest, Secp256k1VerifyResponse}, tx_io::{IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse}};

use crate::key_manager::NetworkKeyProvider;

/// Attestation API trait
#[async_trait]
pub trait AttestationApi {
    /// Get attestation evidence
    async fn get_attestation_evidence(
        &self,
        req: AttestationGetEvidenceRequest,
    ) -> RpcResult<AttestationGetEvidenceResponse>;

    async fn genesis_get_data_handler(
        kp: &dyn NetworkKeyProvider,
    ) -> RpcResult<GenesisDataResponse>; 

    async fn attestation_eval_evidence_handler(
    request: AttestationEvalEvidenceRequest,
    ) -> RpcResult<AttestationEvalEvidenceResponse>; 
}

/// Cryptographic operations API trait
#[async_trait]
pub trait CryptoApi {
    /// Get the public key
    async fn get_public_key(&self,  kp: &dyn NetworkKeyProvider) -> RpcResult<PublicKey>;
    
    /// Sign a message using secp256k1
    async fn secp256k1_sign(
        &self,
        kp: &dyn NetworkKeyProvider,
        req: Secp256k1SignRequest,
    ) -> RpcResult<Secp256k1SignResponse>;
    
    /// Verify a signature using secp256k1
    async fn secp256k1_verify(
        &self,
        kp: &dyn NetworkKeyProvider,
        req: Secp256k1VerifyRequest,
    ) -> RpcResult<Secp256k1VerifyResponse>;
    
    /// Encrypt data
    async fn encrypt(
        &self,
        kp: &dyn NetworkKeyProvider,
        req: IoEncryptionRequest,
    ) -> RpcResult<IoEncryptionResponse>;
    
    /// Decrypt data
    async fn decrypt(
        &self,
        kp: &dyn NetworkKeyProvider,
        req: IoDecryptionRequest,
    ) -> RpcResult<IoDecryptionResponse>;

    async fn get_eph_rng_keypair(&self, kp: &dyn NetworkKeyProvider) -> RpcResult<schnorrkel::keys::Keypair>;
}

