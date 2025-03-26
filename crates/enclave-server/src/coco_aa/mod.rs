pub mod handlers;

use crate::get_secp256k1_pk;

use anyhow::{anyhow, Result};
use attestation_agent::AttestationAPIs;
use attestation_agent::AttestationAgent;
use once_cell::sync::OnceCell;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use std::sync::Arc;
use tokio::sync::Mutex;

pub struct SeismicAttestationAgent {
    inner: AttestationAgent,
    quote_mutex: Mutex<()>,  
}

impl SeismicAttestationAgent {
    /// Create a new SeismicAttestationAgent wrapper
    pub fn new(config_path: Option<&str>) -> Self {
        Self {
            inner: AttestationAgent::new(config_path).expect("Failed to create an AttestationAgent"),
            quote_mutex: Mutex::new(()),
        }
    }

    pub async fn init(&self) -> Result<()> {
        self.inner.init().await
    }

    pub async fn attest_signing_pk(&self, signing_pk: secp256k1::PublicKey) -> Result<(Vec<u8>, secp256k1::PublicKey), anyhow::Error> {
        let signing_pk_bytes = signing_pk.serialize();
        let pk_hash: [u8; 32] = Sha256::digest(signing_pk_bytes.as_slice()).into();

        let att = self.get_evidence(pk_hash.as_slice()).await?;

        Ok((att, signing_pk))
    }

    pub async fn attest_genesis_data(io_pk: secp256k1::PublicKey) -> Result<(GenesisData, Vec<u8>), anyhow::Error> {
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
}

#[async_trait]
impl AttestationAPIs for SeismicAttestationAgent {
    /// Get attestation Token (delegates to inner)
    async fn get_token(&self, token_type: &str) -> Result<Vec<u8>> {
        self.inner.get_token(token_type).await
    }

    /// Get TEE hardware signed evidence with concurrency protection
    async fn get_evidence(&self, runtime_data: &[u8]) -> Result<Vec<u8>> {
        let _lock = self.quote_mutex.lock().await;
        
        self.inner.get_evidence(runtime_data).await
    }

    /// Extend runtime measurement (delegates to inner)
    async fn extend_runtime_measurement(
        &self,
        domain: &str,
        operation: &str,
        content: &str,
        register_index: Option<u64>,
    ) -> Result<()> {
        self.inner.extend_runtime_measurement(domain, operation, content, register_index).await
    }

    /// Bind initdata (delegates to inner)
    async fn bind_init_data(&self, init_data: &[u8]) -> Result<InitDataResult> {
        self.inner.bind_init_data(init_data).await
    }

    /// Get TEE type (delegates to inner)
    fn get_tee_type(&self) -> Tee {
        self.inner.get_tee_type()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[serial(attestation_agent)]
    async fn test_genesis_get_data_handler_success_basic() {
        let attestation_agent = SeismicAttestationAgent::new(None);
        attestation_agent.init().await.unwrap();

        let res = attestation_agent.attest_genesis_data(get_secp256k1_pk()).await.unwrap();
        assert!(!res.evidence.is_empty());
    }

    //#[tokio::test]
    //#[serial(attestation_agent, attestation_service)]
    //async fn test_genesis_get_data_handler_evidence_verifies() {
    //    // handle set up permissions
    //    if !is_sudo() {
    //        panic!("test_eval_evidence_az_tdx: skipped (requires sudo privileges)");
    //    }

    //    // Initialize ATTESTATION_AGENT and ATTESTATION_SERVICE
    //    let attestation_agent = SeismicAttestationAgent::new(None).init().await.unwrap();
    //    init_as_policies()
    //        .await
    //        .expect("Failed to initialize AS policies");

    //    // Make a genesis data request
    //    let res = genesis_get_data_handler().await.unwrap();

    //    // Submit the genesis data to the attestation service
    //    let bytes = res.data.to_bytes().unwrap();
    //    let genesis_data_hash: [u8; 32] = Sha256::digest(bytes).into();

    //    let tdx_eval_request = AttestationEvalEvidenceRequest {
    //        evidence: res.evidence,
    //        tee: Tee::AzTdxVtpm,
    //        runtime_data: Some(ApiData::Raw(genesis_data_hash.to_vec())), // Check that the genesis data hash matches the evidence report_data
    //        runtime_data_hash_algorithm: None,
    //        policy_ids: vec!["allow".to_string()],
    //    };
    //    let res = attestation_eval_evidence_handler(tdx_eval_request)
    //        .await
    //        .unwrap();

    //    assert!(res.eval);
    //}
}
