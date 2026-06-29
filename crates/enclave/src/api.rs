use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use serde::{Deserialize, Serialize};

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

    /// Get the network root key from an existing node, wrapped to this caller.
    ///
    /// Called by a booting/joining node on a peer that already holds the
    /// network root key. `request` is a serialized [`RootKeyRequest`] carrying
    /// the caller's attested ephemeral key + nonce, and the reply is a
    /// serialized [`RootKeyResponse`] carrying the root key AEAD-wrapped under
    /// an ECDH key bound into the attested transcript.
    ///
    /// The wire body is opaque bytes here so this crate need not depend on the
    /// attestation stack.
    ///
    /// [`RootKeyRequest`]: ../../enclave-server/src/bootstrap.rs
    /// [`RootKeyResponse`]: ../../enclave-server/src/bootstrap.rs
    #[method(name = "getWrappedRootKey")]
    async fn get_wrapped_root_key(&self, request: Vec<u8>) -> RpcResult<Vec<u8>>;
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetPurposeKeysResponse {
    pub tx_io_sk: secp256k1::SecretKey,
    pub tx_io_pk: secp256k1::PublicKey,
    pub snapshot_key_bytes: [u8; 32],
    pub rng_keypair: schnorrkel::keys::Keypair,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttestationGetEvidenceResponse {
    pub hcl_report: Vec<u8>,
    pub quote: Vec<u8>,
}
