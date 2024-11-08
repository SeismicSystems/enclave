use serde::{Deserialize, Serialize};
use kbs_types::Tee;

/// Struct representing the request to SnapSync
///
/// # Fields
/// * `client_attestation` - The attestation of the enclave that is running 
///                          the client's node. This attestation must contain an
///                          encryption key as its runtime data.
#[derive(Debug, Serialize, Deserialize)]
pub struct SnapSyncRequest {
    pub tee: Tee,
    pub client_attestation: Vec<u8>,
    pub client_signing_pk: Vec<u8>,
    pub policy_ids: Vec<String>,
}
/// Struct representing the response from SnapSync
///
/// # Fields
/// * `server_attestation` - The attestation of the server enclave. This attestation must contain
///                          an signing pk as its runtime data.
/// * `encrypted_data` - The SnapSyncData, serialized and then encrypted under the clients key.
/// * `signature` - a signature of the snapsync data under the server signing key
#[derive(Debug, Serialize, Deserialize)]
pub struct SnapSyncResponse {
    pub server_attestation: Vec<u8>,
    pub server_signing_pk: Vec<u8>,
    pub encrypted_data: Vec<u8>,
    pub nonce: u64,
    pub signature: Vec<u8>,
}

/// stuct representing the data required to SnapSync
///
/// # Fields
/// * `io_sk` - The secret key of the enclave's IO encryption keypair
/// * `state` - The private state necessary to SnapSync
#[derive(Debug, Serialize, Deserialize)]
pub struct SnapSyncData {
    pub io_sk: Vec<u8>,
    pub state: Vec<u8>, 
}

#[allow(dead_code)]
impl SnapSyncData {
    // Serialize the struct to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Failed to serialize")
    }

    // Deserialize the struct from bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        bincode::deserialize(bytes).expect("Failed to deserialize")
    }
}