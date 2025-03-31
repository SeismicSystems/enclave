use std::collections::HashMap;
use jsonrpsee::core::async_trait;
use anyhow::Result;
use kbs_types::Tee;
use seismic_enclave::genesis::GenesisData;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use attestation_agent::AttestationAPIs;
use attestation_agent::AttestationAgent;
use attestation_agent::InitDataResult;
use attestation_service::token::AttestationTokenBroker;
use attestation_service::Data as OriginalData;
use attestation_service::HashAlgorithm as OriginalHashAlgorithm;


use crate::attestation::verifier::DcapAttVerifier;
// use crate::attestation::verifier::into_original::{IntoOriginalData};
// use attestation_service::HashAlgorithm as OriginalHashAlgorithm;

pub struct SeismicAttestationAgent<T: AttestationTokenBroker + Send + Sync> {
    attestation_agent: AttestationAgent,
    quote_mutex: Mutex<()>,
    verifier: DcapAttVerifier<T>,
}

impl<T: AttestationTokenBroker + Send + Sync> SeismicAttestationAgent<T> {
    /// Create a new SeismicAttestationAgent wrapper
    pub fn new(aa_config_path: Option<&str>, token_broker: T) -> Self {
        Self {
            attestation_agent: AttestationAgent::new(aa_config_path).expect("Failed to create an AttestationAgent"),
            quote_mutex: Mutex::new(()),
            verifier: DcapAttVerifier::new(token_broker),
        }
    }

    pub async fn init(&mut self) -> Result<()> {
        self.attestation_agent.init().await
    }

    pub async fn attest_signing_pk(&self, signing_pk: secp256k1::PublicKey) -> Result<(Vec<u8>, secp256k1::PublicKey), anyhow::Error> {
        let signing_pk_bytes = signing_pk.serialize();
        let pk_hash: [u8; 32] = Sha256::digest(signing_pk_bytes.as_slice()).into();

        let att = self.get_evidence(pk_hash.as_slice()).await?;

        Ok((att, signing_pk))
    }

    pub async fn attest_genesis_data(&self, io_pk: secp256k1::PublicKey) -> Result<(GenesisData, Vec<u8>), anyhow::Error> {
        // For now the genesis data is just the public key of the IO encryption keypair
        // But this is expected to change in the future
        let genesis_data = GenesisData { io_pk };

        // hash the genesis data and attest to it
        let genesis_data_bytes = genesis_data.to_bytes()?;
        let hash_bytes: [u8; 32] = Sha256::digest(genesis_data_bytes).into();

        // Get the evidence from the attestation agent
        let evidence = self 
            .get_evidence(&hash_bytes)
            .await
            .map_err(|e| format!("Error while getting evidence: {:?}", e))
            .unwrap();

        Ok((genesis_data, evidence))
    }
    
    /// Set Attestation Verification Policy.
    pub async fn set_policy(&mut self, policy_id: String, policy: String) -> Result<()> {
        self.verifier.set_policy(policy_id, policy).await?;
        Ok(())
    }

    /// Get Attestation Verification Policy List.
    /// The result is a `policy-id` -> `policy hash` map.
    pub async fn list_policies(&self) -> Result<HashMap<String, String>> {
      self.verifier
            .list_policies()
            .await
    }

    /// Get a single Policy content.
    pub async fn get_policy(&self, policy_id: String) -> Result<String> {
        self.verifier
            .get_policy(policy_id)
            .await
    }

    /// Evaluate evidence against policies
    pub async fn evaluate(
        &self,
        evidence: Vec<u8>,
        tee: Tee,
        runtime_data: Option<OriginalData>,
        runtime_data_hash_algorithm: OriginalHashAlgorithm,
        init_data: Option<OriginalData>,
        init_data_hash_algorithm: OriginalHashAlgorithm,
        policy_ids: Vec<String>,
    ) -> Result<String> {
        self.verifier
            .evaluate(evidence, tee, runtime_data, runtime_data_hash_algorithm, init_data, init_data_hash_algorithm, policy_ids)
            .await
    }
}

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
        self.attestation_agent.extend_runtime_measurement(domain, operation, content, register_index).await
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

