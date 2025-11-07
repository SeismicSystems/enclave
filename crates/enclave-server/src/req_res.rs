use serde::{Deserialize, Serialize};

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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ShareRootKeyResponse {
    pub root_key: [u8; 32],
}
