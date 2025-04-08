use kbs_types::Tee;
use std::net::SocketAddr;

use crate::coco_as::{AttestationEvalEvidenceRequest, Data, HashAlgorithm};
use crate::nonce::Nonce;
use serde::{Deserialize, Serialize};

/// CompleteBoot endpoint is used to signal all boot steps are complete
/// and node should launch the real enclave server and reth
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CompleteBootRequest {}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CompleteBootResponse {
    pub success: bool,
}

/// RetieveRootKey endpoint triggers the enclave to retrieve the root key
/// via http from an existing node running the enclave server
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RetrieveRootKeyRequest {
    pub addr: SocketAddr,
    pub attestation_policy_id: String,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RetrieveRootKeyResponse {}

/// ShareRootKey endpoint triggers the enclave to share the root key with
/// an new enclave server that is booting
///
/// It is expected that the attestation is created with the following parameters:
/// - runtime_data: Some(Data::Raw(req.retriever_pk.serialize().to_vec())),
/// - runtime_data_hash_algorithm: HashAlgorithm::Sha256,
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ShareRootKeyRequest {
    pub evidence: Vec<u8>,
    pub tee: Tee,
    pub retriever_pk: secp256k1::PublicKey,
}
impl Into<AttestationEvalEvidenceRequest> for ShareRootKeyRequest {
    fn into(self) -> AttestationEvalEvidenceRequest {
        AttestationEvalEvidenceRequest {
            evidence: self.evidence,
            tee: self.tee,
            runtime_data: Some(Data::Raw(self.retriever_pk.serialize().to_vec())),
            runtime_data_hash_algorithm: Some(HashAlgorithm::Sha256),
            policy_ids: vec!["share_root".to_string()],
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ShareRootKeyResponse {
    pub nonce: Nonce,
    pub root_key_ciphertext: Vec<u8>,
    pub sharer_pk: secp256k1::PublicKey,
}

/// GenesisBoot endpoint triggers the server to boot in a configuration
/// for a new network genesis
/// For now this just means setting a new root_key from osrng
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GenesisBootRequest {}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GenesisBootResponse {
    pub attestation: Vec<u8>,
}
