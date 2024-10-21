use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationGetEvidenceRequest {
    pub runtime_data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationGetEvidenceResponse {
    pub evidence: Vec<u8>,
}
