use crate::req_res::{
    AttestationGetEvidenceResponse, GetPurposeKeysResponse, ShareRootKeyResponse,
};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

#[rpc(client, server)]
pub trait TdxQuoteRpc {
    /// Health check endpoint that returns "OK" if service is running
    #[method(name = "healthCheck")]
    async fn health_check(&self) -> RpcResult<String>;

    /// Get the secp256k1 public key
    #[method(name = "getPurposeKeys")]
    async fn get_purpose_keys(&self, epoch: u64) -> RpcResult<GetPurposeKeysResponse>;

    /// Generates attestation evidence from the attestation authority
    #[method(name = "getAttestationEvidence")]
    async fn get_attestation_evidence(&self) -> RpcResult<AttestationGetEvidenceResponse>;

    /// Evaluates provided attestation evidence
    #[method(name = "evalAttestationEvidence")]
    async fn eval_attestation_evidence(&self, hcl_report: Vec<u8>, quote: Vec<u8>)
    -> RpcResult<()>;

    /// Shares the root key with an existing node
    #[method(name = "boot.share_root_key")]
    async fn boot_share_root_key(&self, quote: Vec<u8>) -> RpcResult<ShareRootKeyResponse>;

    /// Prepares an encrypted snapshot
    #[method(name = "snapshot.prepare_encrypted_snapshot")]
    async fn prepare_encrypted_snapshot(&self) -> RpcResult<()>;

    /// Restores from an encrypted snapshot
    #[method(name = "snapshot.restore_from_encrypted_snapshot")]
    async fn restore_from_encrypted_snapshot(&self) -> RpcResult<()>;
}
