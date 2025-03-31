use anyhow::{anyhow, Context, Result};
use attestation_agent::AttestationAgent;
use attestation_service::token::simple::{self, Configuration, SimpleAttestationTokenBroker};
use attestation_service::token::{ear_broker, AttestationTokenBroker, AttestationTokenConfig};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use verifier::{
    InitDataHash, ReportData, Verifier,
};

use kbs_types::Tee;
use crypto::HashAlgorithm;

use crate::attestation::agent::SeismicAttestationAgent;


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

/// A lightweight, concurrency-friendly DCAP attestation verifier
pub struct DcapAttVerifier<T: AttestationTokenBroker + Send + Sync> {
    token_broker: T,
}

// Convenience methods for creating DcapAttVerifier with common token broker types
impl DcapAttVerifier<simple::SimpleAttestationTokenBroker> {
    /// Create a new DcapAttVerifier with SimpleAttestationTokenBroker
    pub fn new_simple(config: simple::Configuration) -> Result<Self> {
        let token_broker = simple::SimpleAttestationTokenBroker::new(config)?;
        Ok(Self { token_broker })
    }
    
    /// Create a new DcapAttVerifier with default SimpleAttestationTokenBroker
    pub fn default_simple() -> Result<Self> {
        Self::new_simple(simple::Configuration::default())
    }
}

impl DcapAttVerifier<ear_broker::EarAttestationTokenBroker> {
    /// Create a new DcapAttVerifier with EarAttestationTokenBroker
    pub fn new_ear(config: ear_broker::Configuration) -> Result<Self> {
        let token_broker = ear_broker::EarAttestationTokenBroker::new(config)?;
        Ok(Self { token_broker })
    }
    
    /// Create a new DcapAttVerifier with default EarAttestationTokenBroker
    pub fn default_ear() -> Result<Self> {
        Self::new_ear(ear_broker::Configuration::default())
    }
}

impl<T: AttestationTokenBroker + Send + Sync> DcapAttVerifier<T> {
    /// Create a new DcapAttVerifier instance
    pub fn new(token_broker: T) -> Self {
        Self {
            token_broker
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

#[cfg(test)]
mod tests {
    use crate::{attestation::verifier::ASCoreTokenClaims, utils::{policy_fixture::{PolicyFixture, YOCTO_POLICY_UPDATED}, test_utils::read_vector_txt}};
    use std::env;
    use super::*;
    use tokio::test;
    use sha2::{Digest, Sha256};

    fn test_parse_as_token() {
        match env::current_dir() {
            Ok(path) => println!("Current directory: {}", path.display()),
            Err(e) => eprintln!("Error getting current directory: {}", e),
        }
        let ex_token_path = "../../examples/as_token.txt"; // assumes tests are run from enclaver-server dir
        let ex_token = std::fs::read_to_string(ex_token_path).unwrap();

        let claims = ASCoreTokenClaims::from_jwt(&ex_token).unwrap();

        assert_eq!(claims.tee, "aztdxvtpm");
        let evaluation_reports = serde_json::to_string(&claims.evaluation_reports).unwrap();
        assert_eq!(evaluation_reports, "[{\"policy-hash\":\"b3b555df21b9e952384aec5e81e03e53ca82741da3c5d055ccdb6ba5a85dcc2e6fd1196819dc3c26d09471735275b30a\",\"policy-id\":\"yocto\"}]");
        let tcb_status_map: serde_json::Map<String, Value> =
            serde_json::from_str(&claims.tcb_status).unwrap();
        assert_eq!(
            tcb_status_map.get("aztdxvtpm.quote.body.mr_td"),
            Some(&Value::String("bb379f8e734a755832509f61403f99db2258a70a01e1172a499d6d364101b0675455b4e372a35c1f006541f2de0d7154".to_string()))
        );
        assert_eq!(claims.customized_claims.init_data, Value::Null);
        assert_eq!(claims.customized_claims.runtime_data, Value::Null);
    }

    #[test]
    async fn verifier_test_policy_management() {
        let mut verifier = DcapAttVerifier::<SimpleAttestationTokenBroker>::new_simple(Configuration::default()).unwrap();
        
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
        let policy_id = "yocto".to_string();
        verifier.set_policy(policy_id.clone(), fixture.encode_policy(YOCTO_POLICY_UPDATED)).await.unwrap();
        
        // Verify update
        let retrieved_policy = verifier.get_policy(policy_id.clone()).await.unwrap();
        let encoded_policy = fixture.encode_policy(YOCTO_POLICY_UPDATED);
        assert_eq!(retrieved_policy, encoded_policy);
        
        // Try getting non-existent policy
        let result = verifier.get_policy("non-existent".to_string()).await;
        assert!(result.is_err());
    }
    
    #[test]
    async fn verifier_test_eval_evidence_sample() {
        // Create verifier with the policy fixture
        let mut verifier = DcapAttVerifier::<SimpleAttestationTokenBroker>::new_simple(Configuration::default()).unwrap();
        let fixture = PolicyFixture::new();
        fixture.configure_verifier(&mut verifier).await.unwrap();
        
        // Sample evidence data
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

        let claims = ASCoreTokenClaims::from_jwt(&ex_token).unwrap();
        
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
        // Create verifier with the policy fixture
        let mut verifier = DcapAttVerifier::<SimpleAttestationTokenBroker>::new_simple(Configuration::default()).unwrap();
        let fixture = PolicyFixture::new();
        fixture.configure_verifier(&mut verifier).await.unwrap();
        
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

        let claims = ASCoreTokenClaims::from_jwt(&ex_token).unwrap();
        
        // Verify success
        let allow_reports = &claims_allow.evaluation_reports;
        assert!(!allow_reports.is_empty());
        let first_report = &allow_reports[0];
        assert_eq!(first_report["policy-id"], "allow");
        
        // Evaluate with deny policy - should fail in real implementation
        let raw_claims_deny = verifier.evaluate(
            evidence,
            Tee::Sample,
            runtime_data,
            HashAlgorithm::Sha256,
            None,
            HashAlgorithm::Sha256,
            vec!["deny".to_string()],
        ).await;

        assert!(raw_claims_deny.is_err(), "Reject by policy deny");
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
        
        // Create verifier with the policy fixture
        let mut verifier = DcapAttVerifier::<SimpleAttestationTokenBroker>::new_simple(Configuration::default()).unwrap();
        let fixture = PolicyFixture::new();
        fixture.configure_verifier(&mut verifier).await.unwrap();
        
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
        
        let claims = ASCoreTokenClaims::from_jwt(&ex_token).unwrap();
        
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
        
        // Create verifier with the policy fixture
        let mut verifier = DcapAttVerifier::<SimpleAttestationTokenBroker>::new_simple(Configuration::default()).unwrap();
        let fixture = PolicyFixture::new();
        fixture.configure_verifier(&mut verifier).await.unwrap();
        
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
        
        let claims = ASCoreTokenClaims::from_jwt(&ex_token).unwrap();
        
        // Verify passing results
        assert_eq!(claims_pass.tee, "aztdxvtpm");
        
        // Read TDX evidence that should fail
        let az_tdx_evidence_fail = read_vector_txt(evidence_path_fail.to_string()).unwrap();
        
        // Evaluate the failing evidence
        let raw_claims_fail = verifier.evaluate(
            az_tdx_evidence_fail,
            Tee::AzTdxVtpm,
            Some(Data::Raw(runtime_data_bytes)),
            HashAlgorithm::Sha256,
            None,
            HashAlgorithm::Sha256,
            vec!["yocto".to_string()],
        ).await;

        assert!(raw_claims_fail.is_err(), "Expected rejection by policy 'yocto'");
    }
}
