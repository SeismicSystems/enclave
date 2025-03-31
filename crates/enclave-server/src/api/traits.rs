use jsonrpsee::core::{async_trait, RpcResult};
use secp256k1::PublicKey;
use seismic_enclave::{coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse}, coco_as::{AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse}, genesis::GenesisDataResponse, signing::{Secp256k1SignRequest, Secp256k1SignResponse}, tx_io::{IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse}};

#[async_trait]
pub trait TeeServiceApi {
    // Crypto operations
    async fn get_public_key(&self) -> RpcResult<PublicKey>;
    
    async fn secp256k1_sign(
        &self,
        req: Secp256k1SignRequest,
    ) -> RpcResult<Secp256k1SignResponse>;
    
    async fn encrypt(
        &self,
        req: IoEncryptionRequest,
    ) -> RpcResult<IoEncryptionResponse>;
    
    async fn decrypt(
        &self,
        req: IoDecryptionRequest,
    ) -> RpcResult<IoDecryptionResponse>;
    
    async fn get_eph_rng_keypair(&self) -> RpcResult<schnorrkel::keys::Keypair>;
    
    // Attestation operations
    async fn get_attestation_evidence(
        &self,
        req: AttestationGetEvidenceRequest,
    ) -> RpcResult<AttestationGetEvidenceResponse>;
    
    async fn genesis_get_data_handler(&self) -> RpcResult<GenesisDataResponse>; 
    
    async fn attestation_eval_evidence(
        &self,
        request: AttestationEvalEvidenceRequest,
    ) -> RpcResult<AttestationEvalEvidenceResponse>; 
}

