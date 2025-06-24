use anyhow::Result;
use jsonrpsee::core::async_trait;
use kbs_types::{Tee, TeePubKey};
use std::collections::HashMap;
use tokio::sync::Mutex;

use aa_crypto::HashAlgorithm;
use attestation_agent::AttestationAPIs;
use attestation_agent::AttestationAgent;
use attestation_agent::InitDataResult;
use attestation_service::AttestationService;
use attestation_service::VerificationRequest;

/// a centralized struct for making and verifying attestations
/// includes a mutex because the inner attestation agent is not thread safe
pub struct SeismicAttestationAgent {
    quote_mutex: Mutex<()>,
    attestation_agent: AttestationAgent,
    verifier: AttestationService,
}

impl SeismicAttestationAgent {
    /// Create a new SeismicAttestationAgent wrapper
    pub async fn new(aa_config_path: Option<&str>, as_config: attestation_service::config::Config) -> Self {
        Self {
            quote_mutex: Mutex::new(()),
            attestation_agent: AttestationAgent::new(aa_config_path)
                .expect("Failed to create an AttestationAgent"),
            verifier: AttestationService::new(as_config).await.unwrap(),
        }
    }

    pub async fn init(&mut self) -> Result<()> {
        self.attestation_agent.init().await
    }
}

// delegate attestation_service fn to the inner verifier
impl SeismicAttestationAgent {
    /// Set Attestation Verification Policy.
    pub async fn set_policy(&mut self, policy_id: String, policy: String) -> Result<()> {
        self.verifier.set_policy(policy_id, policy).await
    }

    /// Get Attestation Verification Policy List.
    /// The result is a `policy-id` -> `policy hash` map.
    pub async fn list_policies(&self) -> Result<HashMap<String, String>> {
        self.verifier.list_policies().await
    }

    /// Get a single Policy content.
    pub async fn get_policy(&self, policy_id: String) -> Result<String> {
        self.verifier.get_policy(policy_id).await
    }

    /// Evaluate evidence against policies, verifying the attestation
    pub async fn evaluate(
        &self,
        verification_requests: Vec<VerificationRequest>,
        policy_ids: Vec<String>,
    ) -> Result<String> {
        self.verifier
            .evaluate(
                verification_requests,
                policy_ids,
            )
            .await
    }

    pub async fn register_reference_value(&mut self, message: &str) -> Result<()> {
        self.verifier.register_reference_value(message).await
    }

    pub async fn query_reference_values(&self) -> Result<HashMap<String, Vec<String>>> {
        self.verifier.query_reference_values().await
    }

    pub async fn generate_supplemental_challenge(
        &self,
        tee: Tee,
        tee_parameters: String,
    ) -> Result<String> {
        self.verifier
            .generate_supplemental_challenge(tee, tee_parameters)
            .await
    }
}

/// impl AttestationAPIs for SeismicAttestationAgent for easy use of inner methods
#[async_trait]
impl AttestationAPIs for SeismicAttestationAgent {
    /// Get attestation Token (delegates to attestation_agent)
    async fn get_token(&self, token_type: &str) -> Result<Vec<u8>> {
        self.attestation_agent.get_token(token_type).await
    }

    /// Get TEE hardware signed evidence with concurrency protection
    async fn get_evidence(&self, runtime_data: &[u8]) -> Result<Vec<u8>> {
        let _lock = self.quote_mutex.lock().await;
        self.attestation_agent.get_evidence(runtime_data).await
    }

    /// Get TEE hardware signed evidence (from all attesters) with concurrency protection
    async fn get_additional_evidence(&self, runtime_data: &[u8]) -> Result<Vec<u8>> {
        let _lock = self.quote_mutex.lock().await;
        self.attestation_agent
            .get_additional_evidence(runtime_data)
            .await
    }

    /// Get the composite evidence (primary and additional) with concurrency protection
    async fn get_composite_evidence(
        &self,
        tee_pubkey: TeePubKey,
        nonce: String,
        hash_algorithm: HashAlgorithm,
    ) -> Result<Vec<u8>> {
        let _lock = self.quote_mutex.lock().await;
        self.attestation_agent
            .get_composite_evidence(tee_pubkey, nonce, hash_algorithm)
            .await
    }

    async fn extend_runtime_measurement(
        &self,
        domain: &str,
        operation: &str,
        content: &str,
        register_index: Option<u64>,
    ) -> Result<()> {
        self.attestation_agent
            .extend_runtime_measurement(domain, operation, content, register_index)
            .await
    }

    async fn bind_init_data(&self, init_data: &[u8]) -> Result<InitDataResult> {
        self.attestation_agent.bind_init_data(init_data).await
    }

    fn get_tee_type(&self) -> Tee {
        self.attestation_agent.get_tee_type()
    }
}
