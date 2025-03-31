use kbs_types::Tee;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum::{AsRefStr, Display, EnumString};
use anyhow::{anyhow, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// Hash algorithms used to calculate runtime/init data binding
#[derive(Debug, Display, EnumString, AsRefStr, Serialize, Deserialize, Clone)]
pub enum HashAlgorithm {
    #[strum(ascii_case_insensitive)]
    Sha256,

    #[strum(ascii_case_insensitive)]
    Sha384,

    #[strum(ascii_case_insensitive)]
    Sha512,
}

/// Runtime/Init Data used to check the binding relationship with report data
/// in Evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Data {
    /// This will be used as the expected runtime/init data to check against
    /// the one inside evidence.
    Raw(Vec<u8>),

    /// Runtime/Init data in a JSON map. CoCoAS will rearrange each layer of the
    /// data JSON object in dictionary order by key, then serialize and output
    /// it into a compact string, and perform hash calculation on the whole
    /// to check against the one inside evidence.
    Structured(Value),
}

/// Represents the request to evaluate attestation evidence.
///
/// This struct contains the necessary information for evaluating attestation
/// evidence, including the raw evidence bytes, the TEE (Trusted Execution Environment)
/// type, and optional runtime data and its associated hash algorithm.
///
/// # Fields
///
/// - `evidence`: The raw bytes of the attestation evidence to be evaluated.
/// - `tee`: The TEE type of the attestation evidence, indicating which TEE generated the evidence.
/// - `runtime_data`: The expected runtime data that the evidence should match against. This is optional.
/// - `runtime_data_hash_algorithm`: The hash algorithm to use for the runtime data. This is optional.
///
/// # Notes
///
/// - For the `AzTdxVtpm` TEE, `runtime_data` and `runtime_data_hash_algorithm` must not be `None`.
/// - For empty data in `AzTdxVtpm`, set the following:
///   - `runtime_data = Some(Data::Raw("".into()))`
///   - `runtime_data_hash_algorithm = Some(HashAlgorithm::Sha256)`
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttestationEvalEvidenceRequest {
    pub evidence: Vec<u8>,
    pub tee: Tee,
    pub runtime_data: Option<Data>,
    pub runtime_data_hash_algorithm: Option<HashAlgorithm>,
    pub policy_ids: Vec<String>,
}

/// Represents the response to an attestation evidence evaluation request.
///
/// This struct contains the result of the attestation evaluation, including whether
/// the evidence was deemed valid and any claims extracted from the evidence.
///
/// # Fields
///
/// - `eval`: A boolean indicating whether the attestation service deemed the evidence valid (`true`) or invalid (`false`).
/// - `claims`: A summary of the claims included in the attestation evidence. This may be `None` if there are no claims.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttestationEvalEvidenceResponse {
    pub eval: bool,
    pub claims: Option<ASCoreTokenClaims>,
}

/// Struct representing the relevant fields of an Attestation Service (AS) token's claims.
///
/// This struct contains information about the Trusted Execution Environment (TEE),
/// the evaluation of evidence, and various security properties attested by the AS.
///
/// # Fields
///
/// - `tee` - The TEE type of the attestation evidence.
/// - `evaluation_reports` - A list of policies that the evidence was evaluated against.  
///   More information can be found in the [policy documentation](https://github.com/confidential-containers/trustee/blob/bd6b25add83ece4bb5204b8cf560e0727a7c3f8e/attestation-service/docs/policy.md).
/// - `tcb_status` - The Trusted Computing Base (TCB) status that was attested to.  
///   This is verified against the hardware signature and then checked against a policy.
/// - `reference_data` - Reference values provided by the Reference Value Provider Service (RVPS)  
///   to check against the attestation evidence.
/// - `customized_claims` - The initialization and runtime data that were enforced to match the evidence.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ASCoreTokenClaims {
    pub tee: String,
    #[serde(rename = "evaluation-reports")]
    pub evaluation_reports: Vec<Value>,

    #[serde(rename = "tcb-status")]
    pub tcb_status: String,

    pub customized_claims: ASCustomizedClaims,
}
impl ASCoreTokenClaims {
    /// Serializes the claims to JSON (without JWT encoding).
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    /// Parses a (base64-encoded) JWT string into an `ASCoreTokenClaims`.
    ///
    /// Expects the token to have three parts separated by '.', and
    /// decodes the middle part as JSON claims.
    pub fn from_jwt(token: &str) -> Result<Self> {
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err(anyhow!("Invalid token format: expected 3 parts separated by '.'"));
        }
        let claims_b64 = parts[1];
        let claims_decoded_bytes = URL_SAFE_NO_PAD.decode(claims_b64)?;
        let claims_decoded_string = String::from_utf8(claims_decoded_bytes)?;
        let claims: ASCoreTokenClaims = serde_json::from_str(&claims_decoded_string)?;
        Ok(claims)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ASCustomizedClaims {
    pub init_data: Value,
    pub runtime_data: Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_debug() {
        let request = AttestationEvalEvidenceRequest {
            evidence: vec![1, 2, 3],
            tee: Tee::Sgx,
            runtime_data: Some(Data::Raw(vec![7, 8, 9])),
            runtime_data_hash_algorithm: Some(HashAlgorithm::Sha256),
            policy_ids: vec!["allow".to_string()],
        };

        let debug_output = format!("{:?}", request);

        // The expected debug output
        let expected_output = "AttestationEvalEvidenceRequest { \
        evidence: [1, 2, 3], \
        tee: Sgx, \
        runtime_data: \"Raw([7, 8, 9])\", \
        runtime_data_hash_algorithm: \"Sha256\", \
        policy_ids: [\"allow\"] }";

        assert_eq!(
            debug_output.trim(),
            expected_output.trim(),
            "Debug output does not match expected"
        );

        // Ensure that each key part of the struct is present in the output
        assert!(debug_output.contains("AttestationEvalEvidenceRequest"));
        assert!(debug_output.contains("evidence: [1, 2, 3]"));
        assert!(debug_output.contains("tee: Sgx"));
        assert!(debug_output.contains("runtime_data: \"Raw([7, 8, 9])\""));
        assert!(debug_output.contains("runtime_data_hash_algorithm: \"Sha256\""));
        assert!(debug_output.contains("policy_ids: [\"allow\"]"));
    }

    #[test]
    fn test_serialize_some_data() {
        let original_request = AttestationEvalEvidenceRequest {
            evidence: vec![
                123, 34, 115, 118, 110, 34, 58, 34, 49, 34, 44, 34, 114, 101, 112, 111, 114, 116,
                95, 100, 97, 116, 97, 34, 58, 34, 98, 109, 57, 117, 89, 50, 85, 61, 34, 125,
            ],
            tee: Tee::Sample,
            runtime_data: Some(Data::Raw("nonce".as_bytes().to_vec())),
            runtime_data_hash_algorithm: Some(HashAlgorithm::Sha256),
            policy_ids: vec!["allow".to_string()],
        };

        // Serialize the request to a JSON string
        let serialized = serde_json::to_string(&original_request).expect("Failed to serialize");

        // Deserialize the JSON string back to a `AttestationEvalEvidenceRequest`
        let deserialized: AttestationEvalEvidenceRequest =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        // Check that the deserialized object is equal to the original
        assert_eq!(original_request.evidence, deserialized.evidence);
        assert_eq!(original_request.tee, deserialized.tee);
        match (
            &original_request.runtime_data.unwrap(),
            &deserialized.runtime_data.unwrap(),
        ) {
            (Data::Raw(bytes1), Data::Raw(bytes2)) => assert_eq!(bytes1, bytes2),
            (Data::Structured(value1), Data::Structured(value2)) => assert_eq!(value1, value2),
            _ => panic!("Mismatched runtime data types"),
        }
        assert_eq!(
            original_request
                .runtime_data_hash_algorithm
                .unwrap()
                .to_string(),
            deserialized
                .runtime_data_hash_algorithm
                .unwrap()
                .to_string()
        );
        assert_eq!(original_request.policy_ids, deserialized.policy_ids);
    }

    #[test]
    fn test_serialize_none_hash_algorithm() {
        let original_request = AttestationEvalEvidenceRequest {
            evidence: vec![
                123, 34, 115, 118, 110, 34, 58, 34, 49, 34, 44, 34, 114, 101, 112, 111, 114, 116,
                95, 100, 97, 116, 97, 34, 58, 34, 98, 109, 57, 117, 89, 50, 85, 61, 34, 125,
            ],
            tee: Tee::Sample,
            runtime_data: Some(Data::Raw("nonce".as_bytes().to_vec())),
            runtime_data_hash_algorithm: None,
            policy_ids: vec!["allow".to_string()],
        };

        // Serialize the request to a JSON string
        let serialized = serde_json::to_string(&original_request).expect("Failed to serialize");

        // Deserialize the JSON string back to a `AttestationEvalEvidenceRequest`
        let deserialized: AttestationEvalEvidenceRequest =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        // Check that the deserialized object is equal to the original
        assert_eq!(original_request.evidence, deserialized.evidence);
        assert_eq!(original_request.tee, deserialized.tee);
        match (
            &original_request.runtime_data.unwrap(),
            &deserialized.runtime_data.unwrap(),
        ) {
            (Data::Raw(bytes1), Data::Raw(bytes2)) => assert_eq!(bytes1, bytes2),
            (Data::Structured(value1), Data::Structured(value2)) => assert_eq!(value1, value2),
            _ => panic!("Mismatched runtime data types"),
        }
        assert!(deserialized.runtime_data_hash_algorithm.is_none());
        assert_eq!(original_request.policy_ids, deserialized.policy_ids);
    }

    #[test]
    fn test_serialize_none_data() {
        let original_request = AttestationEvalEvidenceRequest {
            evidence: vec![
                123, 34, 115, 118, 110, 34, 58, 34, 49, 34, 44, 34, 114, 101, 112, 111, 114, 116,
                95, 100, 97, 116, 97, 34, 58, 34, 98, 109, 57, 117, 89, 50, 85, 61, 34, 125,
            ],
            tee: Tee::Sample,
            runtime_data: None,
            runtime_data_hash_algorithm: None,
            policy_ids: vec!["allow".to_string()],
        };

        // Serialize the request to a JSON string
        let serialized = serde_json::to_string(&original_request).expect("Failed to serialize");

        // Deserialize the JSON string back to a `AttestationEvalEvidenceRequest`
        let deserialized: AttestationEvalEvidenceRequest =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        // Check that the deserialized object is equal to the original
        assert_eq!(original_request.evidence, deserialized.evidence);
        assert_eq!(original_request.tee, deserialized.tee);
        assert!(deserialized.runtime_data.is_none());
        assert!(deserialized.runtime_data_hash_algorithm.is_none());
        assert_eq!(original_request.policy_ids, deserialized.policy_ids);
    }
}
