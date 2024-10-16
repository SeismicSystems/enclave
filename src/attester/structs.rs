use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationEvidenceRequest {
    pub runtime_data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationEvidenceResponse {
    pub evidence: Vec<u8>,
}