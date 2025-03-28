use jsonrpsee::core::async_trait;
use anyhow::{anyhow, Result};
use attestation_agent::AttestationAPIs;
use attestation_agent::AttestationAgent;
use attestation_agent::InitDataResult;
use kbs_types::Tee;
use once_cell::sync::OnceCell;
use seismic_enclave::genesis::GenesisData;
use sha2::{Digest, Sha256};
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

    pub async fn init(&mut self) -> Result<()> {
        self.inner.init().await
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

