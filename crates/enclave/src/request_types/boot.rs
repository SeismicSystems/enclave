use serde::{Deserialize, Serialize};

// CompleteBoot endpoint is used to signal all boot steps are complete
// and node should launch the real enclave server and reth
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CompleteBootRequest {}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CompleteBootResponse {
    pub success: bool,
}

// RetieveMasterKey endpoint triggers the enclave to retrieve the master key
// via http from an existing node running the enclave server
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RetieveMasterKeyRequest {
    pub url: String,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RetieveMasterKeyResponse {}

// ShareMasterKey endpoint triggers the enclave to share the master key with
// an new enclave server that is booting
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ShareMasterKeyRequest {
    pub retriever_pk: secp256k1::PublicKey,
    pub attestation: Vec<u8>,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ShareMasterKeyResponse {
    pub master_key_ciphertext: Vec<u8>,
    pub sharer_pk: secp256k1::PublicKey,
    pub attestation: Vec<u8>,
}

// GenesisBoot endpoint triggers the server to boot in a configuration
// for a new network genesis
// For now this just means setting a new master_key from osrng
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GenesisBootRequest {
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GenesisBootResponse {
    pub attestation: Vec<u8>,
}