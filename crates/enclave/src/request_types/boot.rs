use std::net::SocketAddr;

use crate::coco_as::AttestationEvalEvidenceRequest;
use crate::nonce::Nonce;
use serde::{Deserialize, Serialize};

// CompleteBoot endpoint is used to signal all boot steps are complete
// and node should launch the real enclave server and reth
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CompleteBootRequest {}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CompleteBootResponse {
    pub success: bool,
}

// RetieveRootKey endpoint triggers the enclave to retrieve the root key
// via http from an existing node running the enclave server
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RetrieveRootKeyRequest {
    pub addr: SocketAddr,
    pub attestation_policy_id: String,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RetrieveRootKeyResponse {}

// ShareRootKey endpoint triggers the enclave to share the root key with
// an new enclave server that is booting
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ShareRootKeyRequest {
    pub retriever_pk: secp256k1::PublicKey,
    pub attestation: Vec<u8>,
    pub eval_context: AttestationEvalEvidenceRequest,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ShareRootKeyResponse {
    pub nonce: Nonce,
    pub root_key_ciphertext: Vec<u8>,
    pub sharer_pk: secp256k1::PublicKey,
    pub attestation: Vec<u8>,
}

// GenesisBoot endpoint triggers the server to boot in a configuration
// for a new network genesis
// For now this just means setting a new root_key from osrng
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GenesisBootRequest {}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GenesisBootResponse {
    pub attestation: Vec<u8>,
}
