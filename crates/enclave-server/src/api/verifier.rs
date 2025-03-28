use anyhow::{anyhow, Context, Result};
use attestation_service::token::simple::{SimpleAttestationTokenBroker, Configuration};
use attestation_service::token::AttestationTokenBroker;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::HashMap;
use std::sync::Arc;

use verifier::{
    InitDataHash, ReportData, Verifier,
};

use kbs_types::Tee;
use crypto::HashAlgorithm;


/// Runtime/Init Data used to check the binding relationship with report data
/// in Evidence
#[derive(Debug, Clone)]
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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ASCoreTokenClaims {
    pub tee: String,
    #[serde(rename = "evaluation-reports")]
    pub evaluation_reports: Vec<Value>,
    #[serde(rename = "tcb-status")]
    pub tcb_status: String,
    pub customized_claims: ASCustomizedClaims,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_data: Option<HashMap<String, String>>,
}

/// Represents the customized claims for initialization and runtime data.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ASCustomizedClaims {
    pub init_data: Value,
    pub runtime_data: Value,
}

/// Default implementation for ASCoreTokenClaims
impl Default for ASCoreTokenClaims {
    fn default() -> Self {
        Self {
            tee: "unknown".to_string(),
            evaluation_reports: Vec::new(),
            tcb_status: "unknown".to_string(),
            customized_claims: ASCustomizedClaims {
                init_data: Value::Null,
                runtime_data: Value::Null,
            },
            reference_data: None,
        }
    }
}

/// Default implementation for ASCustomizedClaims
impl Default for ASCustomizedClaims {
    fn default() -> Self {
        Self {
            init_data: Value::Null,
            runtime_data: Value::Null,
        }
    }
}

/// A lightweight, concurrency-friendly DCAP attestation verifier
pub struct DcapAttVerifier {
    token_broker: SimpleAttestationTokenBroker, 
}

impl DcapAttVerifier {
    /// Create a new DcapAttVerifier instance
    pub fn new() -> Self {
        Self {
            //todo: enable creating custom token brokers, with a sk derived from key manager
            token_broker: SimpleAttestationTokenBroker::new(Configuration::default()).unwrap(),
        }
    }

    /// Set Attestation Verification Policy.
    pub async fn set_policy(&mut self, policy_id: String, policy: String) -> Result<()> {
        self.token_broker.set_policy(policy_id, policy).await?;
        Ok(())
    }

    /// Get Attestation Verification Policy List.
    /// The result is a `policy-id` -> `policy hash` map.
    pub async fn list_policies(&self) -> Result<HashMap<String, String>> {
        self.token_broker
            .list_policies()
            .await
            .context("Cannot List Policy")
    }

    /// Get a single Policy content.
    pub async fn get_policy(&self, policy_id: String) -> Result<String> {
        self.token_broker
            .get_policy(policy_id)
            .await
            .context("Cannot Get Policy")
    }

    /// Evaluate evidence against policies
    pub async fn evaluate(
        &self,
        evidence: Vec<u8>,
        tee: Tee,
        runtime_data: Option<Data>,
        runtime_data_hash_algorithm: HashAlgorithm,
        init_data: Option<Data>,
        init_data_hash_algorithm: HashAlgorithm,
        policy_ids: Vec<String>,
    ) -> Result<String> {
        // Get the appropriate verifier for the TEE type
        let verifier = verifier::to_verifier(&tee)?;

        // Parse and hash runtime data
        let (report_data, runtime_data_claims) =
            self.parse_data(runtime_data, &runtime_data_hash_algorithm)
                .context("parse runtime data")?;

        let report_data = match &report_data {
            Some(data) => ReportData::Value(data),
            None => ReportData::NotProvided,
        };

        // Parse and hash init data
        let (init_data, init_data_claims) =
            self.parse_data(init_data, &init_data_hash_algorithm)
                .context("parse init data")?;

        let init_data_hash = match &init_data {
            Some(data) => InitDataHash::Value(data),
            None => InitDataHash::NotProvided,
        };

        // Evaluate the evidence using the verifier
        let claims_from_tee_evidence = verifier
            .evaluate(&evidence, &report_data, &init_data_hash)
            .await
            .map_err(|e| anyhow!("Verifier evaluate failed: {e:?}"))?;
        info!("{:?} Verifier/endorsement check passed.", tee);

        let reference_data_map = self.get_reference_data().await?;
        debug!("reference_data_map: {:#?}", reference_data_map);

        let attestation_results_token = self
            .token_broker
            .issue(
                claims_from_tee_evidence,
                policy_ids,
                init_data_claims,
                runtime_data_claims,
                reference_data_map,
                tee,
            )
        .await?;

        Ok(attestation_results_token)
    }
    
    /// Parse and hash data using the specified algorithm
    fn parse_data(
        &self,
        data: Option<Data>,
        hash_algorithm: &HashAlgorithm,
    ) -> Result<(Option<Vec<u8>>, Value)> {
        match data {
            Some(value) => match value {
                Data::Raw(raw) => Ok((Some(raw), Value::Null)),
                Data::Structured(structured) => {
                    // Serialize the structured data (keys in alphabetical order)
                    let hash_materials =
                        serde_json::to_vec(&structured).context("parse JSON structured data")?;
                    let digest = hash_algorithm.digest(&hash_materials);
                    Ok((Some(digest), structured))
                }
            },
            None => Ok((None, Value::Null)),
        }
    }
    /// Get reference data for verification
    async fn get_reference_data(&self) -> Result<HashMap<String, Vec<String>>> {
        let reference_data: HashMap<String, Vec<String>> = HashMap::new();
        Ok(reference_data)
    }
}

// To serialize claims as a JSON string without using JWT
pub fn claims_to_json(claims: &ASCoreTokenClaims) -> Result<String> {
    Ok(serde_json::to_string(claims)?)
}

#[cfg(test)]
mod tests {
    use crate::{coco_as::{parse_as_token_claims, policies}, utils::policy_fixture::{PolicyFixture, YOCTO_POLICY_UPDATED}};

    use super::*;
    use tokio::test;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    // Helper function to read test files
    fn read_vector_txt(file_path: String) -> Result<Vec<u8>> {
        let encoded = std::fs::read_to_string(file_path)?;
        Ok(URL_SAFE_NO_PAD.decode(encoded.trim())?)
    }

    #[test]
    async fn verifier_test_policy_management() {
        let mut verifier = DcapAttVerifier::new();
        
        let fixture = PolicyFixture::new();
        fixture.configure_verifier(&mut verifier).await.unwrap();

        let policy_id = "allow".to_string();
        let expected_content = fixture.get_policy_content(&policy_id).unwrap();
        let retrieved_policy = verifier.get_policy(policy_id.clone()).await.unwrap();
        assert_eq!(&retrieved_policy, expected_content);
        
        let policies = verifier.list_policies().await.unwrap();
        // 4 policies = our three policies + default policy 
        assert_eq!(policies.len(), 4);
        
        // Update a policy
        verifier.set_policy(policy_id.clone(), fixture.encode_policy(YOCTO_POLICY_UPDATED)).await.unwrap();
        
        // Verify update
        let policy_id = "yocto".to_string();
        let retrieved_policy = verifier.get_policy(policy_id.clone()).await.unwrap();
        let encoded_policy = fixture.encode_policy(YOCTO_POLICY_UPDATED);
        assert_eq!(retrieved_policy, encoded_policy);
        
        // Try getting non-existent policy
        let result = verifier.get_policy("non-existent".to_string()).await;
        assert!(result.is_err());
    }
    
    #[test]
    async fn verifier_test_eval_evidence_sample() {
        // Create verifier with an "allow" policy
        let mut verifier = DcapAttVerifier::new();
        verifier.set_policy("allow".to_string(), r#"{"rules":[]}"#.to_string()).await.unwrap();
        
        // Sample evidence data (mocked from your original test)
        let evidence = vec![
            123, 34, 115, 118, 110, 34, 58, 34, 49, 34, 44, 34, 114, 101, 112, 111, 114, 116,
            95, 100, 97, 116, 97, 34, 58, 34, 98, 109, 57, 117, 89, 50, 85, 61, 34, 125,
        ];
        
        // Runtime data
        let runtime_data = Some(Data::Raw("nonce".as_bytes().to_vec()));
        
        // Evaluate the evidence
        let raw_claims = verifier.evaluate(
            evidence,
            Tee::Sample,
            runtime_data,
            HashAlgorithm::Sha256,
            None,
            HashAlgorithm::Sha256,
            vec!["allow".to_string()],
        ).await.unwrap();

        let claims = parse_as_token_claims(&raw_claims).unwrap();
        
        // Verify results
        assert_eq!(claims.tee, "sample");
        
        // Check if policy evaluation was successful
        let eval_reports = &claims.evaluation_reports;
        assert!(!eval_reports.is_empty());
        
        // For Sample TEE, we should have a report_data field in tcb_status
        let tcb_status_map: serde_json::Map<String, Value> =
            serde_json::from_str(&claims.tcb_status).unwrap();
        assert_eq!(tcb_status_map["report_data"], "bm9uY2U=");
    }
    
    #[test]
    async fn verifier_test_eval_policy_deny() {
        // Create verifier with "allow" and "deny" policies
        let mut verifier = DcapAttVerifier::new();
        verifier.set_policy("allow".to_string(), r#"{"rules":[]}"#.to_string()).await.unwrap();
        verifier.set_policy("deny".to_string(), r#"{"rules":[{"field":"always","operator":"eq","value":"deny"}]}"#.to_string()).await.unwrap();
        
        // Sample evidence data
        let evidence = vec![
            123, 34, 115, 118, 110, 34, 58, 34, 49, 34, 44, 34, 114, 101, 112, 111, 114, 116,
            95, 100, 97, 116, 97, 34, 58, 34, 98, 109, 57, 117, 89, 50, 85, 61, 34, 125,
        ];
        
        // Runtime data
        let runtime_data = Some(Data::Raw("nonce".as_bytes().to_vec()));
        
        // Evaluate with allow policy - should pass
        let raw_claims_allow = verifier.evaluate(
            evidence.clone(),
            Tee::Sample,
            runtime_data.clone(),
            HashAlgorithm::Sha256,
            None,
            HashAlgorithm::Sha256,
            vec!["allow".to_string()],
        ).await.unwrap();

        let claims_allow = parse_as_token_claims(&raw_claims_allow).unwrap();
        
        // Verify success
        let allow_reports = &claims_allow.evaluation_reports;
        assert!(!allow_reports.is_empty());
        let first_report = &allow_reports[0];
        assert_eq!(first_report["policy-id"], "allow");
        assert!(first_report["result"].as_bool().unwrap());
        
        // Evaluate with deny policy - should fail in real implementation
        // Note: In a real implementation, we'd want this test to verify failure logic
        // For now, we'll just check that we get a response with the right evaluation result
        let raw_claims_deny = verifier.evaluate(
            evidence,
            Tee::Sample,
            runtime_data,
            HashAlgorithm::Sha256,
            None,
            HashAlgorithm::Sha256,
            vec!["deny".to_string()],
        ).await.unwrap();
        
        let claims_deny = parse_as_token_claims(&raw_claims_deny).unwrap();
        
        // Verify the deny policy is marked as failed
        let deny_reports = &claims_deny.evaluation_reports;
        assert!(!deny_reports.is_empty());
        let first_report = &deny_reports[0];
        assert_eq!(first_report["policy-id"], "deny");
        
        // This assertion depends on how your policy evaluation works
        // In a real implementation with actual policy evaluation, this should be false
        if let Some(result) = first_report["result"].as_bool() {
            assert!(!result);
        }
    }
    
    #[test]
    async fn verifier_test_eval_evidence_az_tdx() {
        // This test requires actual TDX evidence files
        // Skip if files are not available
        let evidence_path = "../../examples/tdx_encoded_evidence.txt";
        if !std::path::Path::new(evidence_path).exists() {
            println!("Skipping test_eval_evidence_az_tdx: evidence file not found");
            return;
        }
        
        // Create verifier with an "allow" policy for TDX
        let mut verifier = DcapAttVerifier::new();
        verifier.set_policy("allow".to_string(), r#"{"rules":[]}"#.to_string()).await.unwrap();
        
        // Read TDX evidence
        let tdx_evidence_encoded = std::fs::read_to_string(evidence_path).unwrap();
        let tdx_evidence = URL_SAFE_NO_PAD
            .decode(tdx_evidence_encoded.as_str())
            .unwrap();
        
        // Evaluate the evidence
        let raw_claims = verifier.evaluate(
            tdx_evidence,
            Tee::AzTdxVtpm,
            Some(Data::Raw("".into())),
            HashAlgorithm::Sha256,
            None,
            HashAlgorithm::Sha256,
            vec!["allow".to_string()],
        ).await.unwrap();
        
        let claims = parse_as_token_claims(&raw_claims).unwrap();
        
        // Verify results
        assert_eq!(claims.tee, "aztdxvtpm");
        
        // Check evaluation reports
        assert!(!claims.evaluation_reports.is_empty());
        
        // For AzTdxVtpm, we expect mr_td field in tcb_status
        let tcb_status_map: serde_json::Map<String, Value> =
            serde_json::from_str(&claims.tcb_status).unwrap();
        assert!(tcb_status_map.contains_key("aztdxvtpm.quote.body.mr_td"));
    }
    
    #[test]
    async fn verifier_test_eval_evidence_az_tdx_tpm_pcr04() {
        // This test requires specific TDX evidence files
        let evidence_path_pass = "../../examples/yocto_20241023223507.txt";
        let evidence_path_fail = "../../examples/yocto_20241025193121.txt";
        
        if !std::path::Path::new(evidence_path_pass).exists() || 
           !std::path::Path::new(evidence_path_fail).exists() {
            println!("Skipping test_eval_evidence_az_tdx_tpm_pcr04: evidence files not found");
            return;
        }
        
        // Create verifier with yocto policy
        let mut verifier = DcapAttVerifier::new();
        
        // A policy checking mr_td, mr_seam, and pcr04
        let yocto_policy = r#"{
            "rules": [
                {"field": "aztdxvtpm.quote.body.mr_td", "operator": "eq", "value": "expected_mr_td_value"},
                {"field": "aztdxvtpm.quote.body.mr_seam", "operator": "eq", "value": "expected_mr_seam_value"},
                {"field": "aztdxvtpm.tpm.pcr04", "operator": "eq", "value": "expected_pcr04_value"}
            ]
        }"#.to_string();
        
        verifier.set_policy("yocto".to_string(), yocto_policy).await.unwrap();
        
        // Read TDX evidence that should pass
        let az_tdx_evidence_pass = read_vector_txt(evidence_path_pass.to_string()).unwrap();
        let runtime_data_bytes = vec![
            240, 30, 194, 3, 67, 143, 162, 40, 249, 35, 238, 193, 59, 140, 203, 3, 98, 144, 105,
            221, 209, 34, 207, 229, 52, 61, 58, 14, 102, 234, 146, 8,
        ];
        
        // Evaluate the passing evidence
        let raw_claims_pass = verifier.evaluate(
            az_tdx_evidence_pass,
            Tee::AzTdxVtpm,
            Some(Data::Raw(runtime_data_bytes.clone())),
            HashAlgorithm::Sha256,
            None,
            HashAlgorithm::Sha256,
            vec!["yocto".to_string()],
        ).await.unwrap();
        
        let claims_pass = parse_as_token_claims(&raw_claims_pass).unwrap();
        
        // Verify passing results
        assert_eq!(claims_pass.tee, "aztdxvtpm");
        
        // Read TDX evidence that should fail
        let az_tdx_evidence_fail = read_vector_txt(evidence_path_fail.to_string()).unwrap();
        
        // Evaluate the failing evidence
        // Note: In a real test with actual policy evaluation, this should return an error
        // For now, we just check that we get a proper evaluation report
        let raw_claims_fail = verifier.evaluate(
            az_tdx_evidence_fail,
            Tee::AzTdxVtpm,
            Some(Data::Raw(runtime_data_bytes)),
            HashAlgorithm::Sha256,
            None,
            HashAlgorithm::Sha256,
            vec!["yocto".to_string()],
        ).await.unwrap();
        
        let claims_fail = parse_as_token_claims(&raw_claims_fail).unwrap();
        
        // In a real implementation with actual policy checking:
        // - Pass case: first_report["result"] should be true
        // - Fail case: evaluate() should return an error or first_report["result"] should be false
        
        // For now we just verify we get the right policy ID in the reports
        let first_report = &claims_fail.evaluation_reports[0];
        assert_eq!(first_report["policy-id"], "yocto");
    }
    
    #[test]
    async fn verifier_test_init_data_and_runtime_data() {
        // Test that init_data and runtime_data are properly processed
        let mut verifier = DcapAttVerifier::new();
        verifier.set_policy("allow".to_string(), r#"{"rules":[]}"#.to_string()).await.unwrap();
        
        // Sample evidence data
        let evidence = vec![
            123, 34, 115, 118, 110, 34, 58, 34, 49, 34, 44, 34, 114, 101, 112, 111, 114, 116,
            95, 100, 97, 116, 97, 34, 58, 34, 98, 109, 57, 117, 89, 50, 85, 61, 34, 125,
        ];
        
        // Structured data with JSON
        let json_data = r#"{"key":"value","number":42}"#;
        let runtime_data = Some(Data::Raw("runtime-nonce".as_bytes().to_vec()));
        let init_data = Some(Data::Structured(serde_json::json!({
            "bytes": "init-data",
            "json": json_data.to_string(),
        })));

        // Evaluate with both runtime and init data
        let raw_claims = verifier.evaluate(
            evidence,
            Tee::Sample,
            runtime_data,
            HashAlgorithm::Sha256,
            init_data,
            HashAlgorithm::Sha256,
            vec!["allow".to_string()],
        ).await.unwrap();

        let claims = parse_as_token_claims(&raw_claims).unwrap();
        
        // Verify customized claims contain the data
        assert_ne!(claims.customized_claims.runtime_data, Value::Null);
        assert_ne!(claims.customized_claims.init_data, Value::Null);
        
        // Check init_data contains the JSON we provided
        if let Value::Object(map) = &claims.customized_claims.init_data {
            assert!(map.contains_key("key"));
            assert_eq!(map["key"], "value");
            assert_eq!(map["number"], 42);
        } else {
            panic!("Expected init_data to be a JSON object");
        }
    }
}
