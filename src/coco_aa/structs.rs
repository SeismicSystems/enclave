use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationGetEvidenceRequest {
    // For AzTdxVtpm, this affects the quotes's aztdxvtpm.quote.body.report_data
    pub runtime_data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationGetEvidenceResponse {
    pub evidence: Vec<u8>,
}
