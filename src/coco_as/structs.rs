use attestation_service::{Data, HashAlgorithm};
use kbs_types::Tee;
// use serde::{Deserialize, Serialize};
use std::fmt;


pub struct AttestationEvalEvidenceRequest {
    pub evidence: Vec<u8>,
    pub tee: Tee,
    pub runtime_data: Vec<Data>,
    pub runtime_data_hash_algorithm: Option<HashAlgorithm>,
    // pub init_data: Option<Data>,
    // pub init_data_hash_algorithm: Option<HashAlgorithm>,
    // pub policy_ids: Vec<String>,
}

impl fmt::Debug for AttestationEvalEvidenceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttestationEvalEvidenceRequest")
            .field("evidence", &self.evidence)
            .field("tee", &self.tee)
            .field("runtime_data", &format_args!("[{} items]", self.runtime_data.len())) // Placeholder if `Data` doesn't implement Debug
            .field("runtime_data_hash_algorithm", &match &self.runtime_data_hash_algorithm {
                Some(alg) => format!("{:?}", alg.to_string()),
                None => "None".to_string(),
            })
            .finish()
    }
}

