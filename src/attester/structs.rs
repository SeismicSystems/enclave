use serde::{Deserialize, Serialize};
use kbs_types::Tee;

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationEvidenceRequest {
    pub runtime_data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationEvidenceResponse {
    pub evidence: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtendRuntimeMeasurementRequest {
    pub domain: String,
    pub operation: String,
    pub content: String,
    pub register_index: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckInitDataRequest {
    pub init_data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckInitDataResponse {
    pub check_passed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TeeTypeResponse {
    pub tee_type: Tee,
}