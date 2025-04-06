use anyhow::Result;
use jsonrpsee::core::async_trait;
use kbs_types::Tee;
use std::collections::HashMap;
use tokio::sync::Mutex;

use attestation_agent::AttestationAPIs;
use attestation_agent::AttestationAgent;
use attestation_agent::InitDataResult;
use attestation_service::token::simple::SimpleAttestationTokenBroker;
use attestation_service::token::AttestationTokenBroker;
use attestation_service::Data;
use attestation_service::HashAlgorithm;

use crate::attestation::verifier::DcapAttVerifier;

/// a centralized struct for making and verifying attestations
/// includes a mutex because the inner attestation agent is not thread safe
pub struct SeismicAttestationAgent<T: AttestationTokenBroker + Send + Sync> {
    attestation_agent: AttestationAgent,
    quote_mutex: Mutex<()>,
    verifier: DcapAttVerifier<T>,
}

impl<T: AttestationTokenBroker + Send + Sync> SeismicAttestationAgent<T> {
    /// Create a new SeismicAttestationAgent wrapper
    pub fn new(aa_config_path: Option<&str>, token_broker: T) -> Self {
        Self {
            attestation_agent: AttestationAgent::new(aa_config_path)
                .expect("Failed to create an AttestationAgent"),
            quote_mutex: Mutex::new(()),
            verifier: DcapAttVerifier::new(token_broker),
        }
    }

    pub async fn init(&mut self) -> Result<()> {
        self.attestation_agent.init().await
    }

    /// Set Attestation Verification Policy.
    pub async fn set_policy(&mut self, policy_id: String, policy: String) -> Result<()> {
        self.verifier.set_policy(policy_id, policy).await?;
        Ok(())
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
        evidence: Vec<u8>,
        tee: Tee,
        runtime_data: Option<Data>,
        runtime_data_hash_algorithm: HashAlgorithm,
        init_data: Option<Data>,
        init_data_hash_algorithm: HashAlgorithm,
        policy_ids: Vec<String>,
    ) -> Result<String> {
        self.verifier
            .evaluate(
                evidence,
                tee,
                runtime_data,
                runtime_data_hash_algorithm,
                init_data,
                init_data_hash_algorithm,
                policy_ids,
            )
            .await
    }
}

/// impl AttestationAPIs for SeismicAttestationAgent for easy use of inner methods
#[async_trait]
impl<T: AttestationTokenBroker + Send + Sync> AttestationAPIs for SeismicAttestationAgent<T> {
    /// Get attestation Token (delegates to attestation_agent)
    async fn get_token(&self, token_type: &str) -> Result<Vec<u8>> {
        self.attestation_agent.get_token(token_type).await
    }

    /// Get TEE hardware signed evidence with concurrency protection
    async fn get_evidence(&self, runtime_data: &[u8]) -> Result<Vec<u8>> {
        let _lock = self.quote_mutex.lock().await;

        self.attestation_agent.get_evidence(runtime_data).await
    }

    /// Extend runtime measurement (delegates to attestation_agent)
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

    /// Bind initdata (delegates to attestation_agent)
    async fn bind_init_data(&self, init_data: &[u8]) -> Result<InitDataResult> {
        self.attestation_agent.bind_init_data(init_data).await
    }

    /// Get TEE type (delegates to attestation_agent)
    fn get_tee_type(&self) -> Tee {
        self.attestation_agent.get_tee_type()
    }
}

/// A reasonable default mock attestation agent for testing
pub fn seismic_aa_mock() -> SeismicAttestationAgent<SimpleAttestationTokenBroker> {
    let v_token_broker = SimpleAttestationTokenBroker::new(
        attestation_service::token::simple::Configuration::default(),
    )
    .expect("Failed to create an AttestationAgent");
    let saa = SeismicAttestationAgent::new(None, v_token_broker);
    saa
}
