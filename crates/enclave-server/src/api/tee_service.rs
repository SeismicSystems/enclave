use std::sync::Arc;

use attestation_service::token::{ear_broker, simple};
use log::error;
use jsonrpsee::core::{async_trait, RpcResult};
use seismic_enclave::coco_as::{ASCoreTokenClaims, AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse};
use seismic_enclave::genesis::GenesisDataResponse;

use crate::key_manager::NetworkKeyProvider;
use seismic_enclave::coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse};

use seismic_enclave::signing::{Secp256k1SignRequest, Secp256k1SignResponse};
use seismic_enclave::tx_io::{IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse};
use seismic_enclave::{ecdh_decrypt, ecdh_encrypt, rpc_bad_argument_error, rpc_bad_evidence_error, rpc_bad_genesis_error, rpc_bad_quote_error, rpc_invalid_ciphertext_error, secp256k1_sign_digest};

use crate::attestation::agent::SeismicAttestationAgent;
use super::traits::TeeServiceApi;
use attestation_agent::AttestationAPIs;

pub type DefaultTeeService<K> = TeeService<K, Box<dyn AttestationTokenBroker + Send + Sync>>;

pub struct TeeService<K: NetworkKeyProvider, T: AttestationTokenBroker + Send + Sync + 'static> {
    key_provider: Arc<K>,
    attestation_agent: Arc<SeismicAttestationAgent<T>>,
}

impl<K: NetworkKeyProvider, T: AttestationTokenBroker + Send + Sync + 'static> TeeService<K, T> {
    pub fn new(key_provider: Arc<K>, attestation_agent: Arc<SeismicAttestationAgent<T>>) -> Self {
        Self { 
            key_provider,
            attestation_agent,
        }
    }
}

// Implementation for boxed trait version (most flexible)
impl<K: NetworkKeyProvider> TeeService<K, Box<dyn AttestationTokenBroker + Send + Sync>> {
    // Factory method to create with default configuration
    pub async fn with_default_attestation(key_provider: K, config_path: Option<&str>) -> Result<Self, anyhow::Error> {

        let attestation_agent = SeismicAttestationAgent::new(config_path)?;
        let attestation_agent = Arc::new(attestation_agent);
        
        // Initialize the attestation agent
        Arc::clone(&attestation_agent).init().await?;
        
        Ok(Self::new(Arc::new(key_provider), attestation_agent))
    }
    
    // Factory method with custom token broker configuration
    pub async fn with_token_config(
        key_provider: K, 
        config_path: Option<&str>, 
        token_config: AttestationTokenConfig
    ) -> Result<Self, anyhow::Error> {
        let attestation_agent = SeismicAttestationAgent::with_token_config(config_path, token_config)?;
        let attestation_agent = Arc::new(attestation_agent);
        
        // Initialize the attestation agent
        Arc::clone(&attestation_agent).init().await?;
        
        Ok(Self::new(Arc::new(key_provider), attestation_agent))
    }
}

// Convenience implementations for specific token broker types
impl<K: NetworkKeyProvider> TeeService<K, simple::SimpleAttestationTokenBroker> {
    pub async fn with_simple_broker(
        key_provider: K,
        config_path: Option<&str>,
        broker_config: Option<simple::Configuration>,
    ) -> Result<Self, anyhow::Error> {
        let attestation_agent = match broker_config {
            Some(config) => SeismicAttestationAgent::new_simple(config_path, config)?,
            None => SeismicAttestationAgent::default_simple(config_path)?,
        };
        let attestation_agent = Arc::new(attestation_agent);
        
        // Initialize the attestation agent
        Arc::clone(&attestation_agent).init().await?;
        
        Ok(Self::new(Arc::new(key_provider), attestation_agent))
    }
}

impl<K: NetworkKeyProvider> TeeService<K, ear_broker::EarAttestationTokenBroker> {
    pub async fn with_ear_broker(
        key_provider: K,
        config_path: Option<&str>,
        broker_config: Option<ear_broker::Configuration>,
    ) -> Result<Self, anyhow::Error> {
        let attestation_agent = match broker_config {
            Some(config) => SeismicAttestationAgent::new_ear(config_path, config)?,
            None => SeismicAttestationAgent::default_ear(config_path)?,
        };
        let attestation_agent = Arc::new(attestation_agent);
        
        // Initialize the attestation agent
        Arc::clone(&attestation_agent).init().await?;
        
        Ok(Self::new(Arc::new(key_provider), attestation_agent))
    }
}

#[async_trait]
impl<K: NetworkKeyProvider + Send + Sync + 'static> TeeServiceApi for TeeService<K> {
    // Crypto operations implementations
    async fn get_public_key(&self) -> RpcResult<secp256k1::PublicKey> {
        Ok(self.key_provider.get_tx_io_pk())
    }

    async fn secp256k1_sign(
        &self,
        req: Secp256k1SignRequest,
    ) -> RpcResult<Secp256k1SignResponse> {
        let sk = self.key_provider.get_tx_io_sk();
        let signature = secp256k1_sign_digest(&req.msg, sk)
            .map_err(|e| rpc_bad_argument_error(anyhow::anyhow!(e)))?;
        Ok(Secp256k1SignResponse { sig: signature })
    }

    async fn encrypt(
        &self,
        req: IoEncryptionRequest,
    ) -> RpcResult<IoEncryptionResponse> {
        let sk = self.key_provider.get_tx_io_sk();
        let encrypted_data = match ecdh_encrypt(&req.key, &sk, &req.data, req.nonce) {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to encrypt data: {}", e);
                return Err(rpc_bad_argument_error(e));
            }
        };
        
        Ok(IoEncryptionResponse { encrypted_data })
    }

    async fn decrypt(
        &self,
        req: IoDecryptionRequest,
    ) -> RpcResult<IoDecryptionResponse> {
        let sk = self.key_provider.get_tx_io_sk();
        let decrypted_data = match ecdh_decrypt(
            &req.key,
            &sk,
            &req.data,
            req.nonce,
        ) {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to decrypt data: {}", e);
                return Err(rpc_invalid_ciphertext_error(e));
            }
        };
        
        Ok(IoDecryptionResponse { decrypted_data })
    }
    
    async fn get_eph_rng_keypair(&self) -> RpcResult<schnorrkel::keys::Keypair> {
        Ok(self.key_provider.get_rng_keypair())
    }
    
    // Attestation operations implementations - now using SeismicAttestationAgent
    async fn get_attestation_evidence(
        &self,
        req: AttestationGetEvidenceRequest,
    ) -> RpcResult<AttestationGetEvidenceResponse> {
        // Use SeismicAttestationAgent's mutex-protected get_evidence method
        // The mutex handling is already implemented in the agent
        let evidence = match self.attestation_agent.get_evidence(req.runtime_data.as_slice()).await {
            Ok(evidence) => evidence,
            Err(e) => {
                error!("Failed to get attestation evidence: {}", e);
                return Err(rpc_bad_quote_error(anyhow::anyhow!("Issue in getting the evidence")));
            }
        };
        
        Ok(AttestationGetEvidenceResponse { evidence })
    }

    async fn genesis_get_data_handler(&self) -> RpcResult<GenesisDataResponse> {
        let io_pk = self.key_provider.get_tx_io_pk();
        
        // Use the agent's attest_genesis_data method which handles the mutex internally
        let (genesis_data, evidence) = match self.attestation_agent.attest_genesis_data(io_pk).await {
            Ok(result) => result,
            Err(e) => {
                error!("Failed to attest genesis data: {}", e);
                return Err(rpc_bad_genesis_error(anyhow::anyhow!("Issue in attesting genesis data")));
            }
        };

        Ok(GenesisDataResponse {
            data: genesis_data,
            evidence,
        })
    }

    async fn attestation_eval_evidence(
        &self,
        request: AttestationEvalEvidenceRequest,
    ) -> RpcResult<AttestationEvalEvidenceResponse> {
        // Convert the request's runtime data hash algorithm to the original enum
        let runtime_data: Option<OriginalData> = request.runtime_data.map(|data| data.into_original());
        let runtime_data_hash_algorithm: OriginalHashAlgorithm =
            match request.runtime_data_hash_algorithm {
                Some(alg) => alg.into_original(),
                None => OriginalHashAlgorithm::Sha256,
            };

        // Evaluate attestation evidence (no lock needed for evaluation)
        let eval_result = eval_att_evidence(
            request.evidence,
            request.tee,
            runtime_data,
            runtime_data_hash_algorithm,
            None,
            OriginalHashAlgorithm::Sha256,
            request.policy_ids,
        )
        .await;

        let as_token: String = match eval_result {
            Ok(as_token) => as_token,
            Err(e) => {
                error!("Failed to evaluate attestation evidence: {}", e);
                return Err(rpc_bad_evidence_error(e));
            }
        };

        let claims: ASCoreTokenClaims = match parse_as_token_claims(&as_token) {
            Ok(claims) => claims,
            Err(e) => {
                error!("Failed to parse AS token: {}", e);
                return Err(rpc_bad_argument_error(anyhow::anyhow!(
                    "Error while parsing AS token: {e}"
                )));
            }
        };

        Ok(AttestationEvalEvidenceResponse {
            eval: true,
            claims: Some(claims),
        })
    }
}


#[cfg(test)]
mod tests {
    use crate::utils::test_utils::{is_sudo, read_vector_txt};
    use super::*;
    use seismic_enclave::coco_as::{Data, HashAlgorithm};

    use serial_test::serial;
    use std::env;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use kbs_types::Tee;
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use crate::key_manager::builder::KeyManagerBuilder;
    
    use seismic_enclave::{nonce::Nonce, get_unsecure_sample_secp256k1_pk};

    #[tokio::test]
    async fn test_secp256k1_sign() {
        // Prepare sign request body
        let msg_to_sign: Vec<u8> = vec![84, 101, 115, 116, 32, 77, 101, 115, 115, 97, 103, 101]; // "Test Message"
        let sign_request = Secp256k1SignRequest {
            msg: msg_to_sign.clone(),
        };
        let kp = KeyManagerBuilder::build_mock().unwrap();

        let tee_service = TeeService::with_default_attestation(kp, None).await.unwrap();

        let res = tee_service.secp256k1_sign(sign_request).await.unwrap();
        assert!(!res.sig.is_empty());
    }

    #[tokio::test]
    async fn test_io_encryption() {
        // Prepare encryption request body
        let data_to_encrypt = vec![72, 101, 108, 108, 111];
        let nonce = Nonce::new_rand();
        let req = IoEncryptionRequest {
            key: get_unsecure_sample_secp256k1_pk(),
            data: data_to_encrypt.clone(),
            nonce: nonce.clone().into(),
        };
        let kp = KeyManagerBuilder::build_mock().unwrap();

        let tee_service = TeeService::with_default_attestation(kp, None).await.unwrap();
        
        let res = tee_service.encrypt(req).await.unwrap();

        // check that decryption returns the original data
        // Prepare decrypt request body
        let req = IoDecryptionRequest {
            key: get_unsecure_sample_secp256k1_pk(),
            data: res.encrypted_data,
            nonce: nonce.clone(),
        };

        let res = tee_service.decrypt(req).await.unwrap();

        assert_eq!(res.decrypted_data, data_to_encrypt);
    }

    #[tokio::test]
    async fn test_decrypt_invalid_ciphertext() {
        let bad_ciphertext = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let nonce = Nonce::new_rand();
        let decryption_request = IoDecryptionRequest {
            key: get_unsecure_sample_secp256k1_pk(),
            data: bad_ciphertext,
            nonce: nonce.clone(),
        };
        let kp = KeyManagerBuilder::build_mock().unwrap();
        let tee_service = TeeService::with_default_attestation(kp, None).await.unwrap();
        let res = tee_service.decrypt(decryption_request).await;

        assert_eq!(res.is_err(), true);
        assert_eq!(
            res.err()
                .unwrap()
                .to_string()
                .contains("Invalid ciphertext"),
            true
        );
    }

    #[tokio::test]
    #[serial(attestation_agent)]
    async fn test_attestation_evidence_handler_valid_request_sample() {
        // NOTE: This test will run with the Sample TEE Type
        // because it doesn't run with sudo privileges

        init_coco_aa().expect("Failed to initialize AttestationAgent");

        // Mock a valid AttestationGetEvidenceRequest
        let runtime_data = "nonce".as_bytes(); // Example runtime data
        let evidence_request = AttestationGetEvidenceRequest {
            runtime_data: runtime_data.to_vec(),
        };
        
        let kp = KeyManagerBuilder::build_mock().unwrap();
        let tee_service = TeeService::with_default_attestation(kp, None).await.unwrap();
        
        // Call the handler
        let res = tee_service.get_attestation_evidence(evidence_request)
            .await
            .unwrap();

        // Ensure the response is not empty
        assert!(!res.evidence.is_empty());
    }

    #[tokio::test]
    #[serial(attestation_agent)]
    async fn test_attestation_evidence_handler_aztdxvtpm_runtime_data() {
        // handle set up permissions
        if !is_sudo() {
            panic!("test_eval_evidence_az_tdx: skipped (requires sudo privileges)");
        }

        init_coco_aa().expect("Failed to initialize AttestationAgent");

        // Make requests with different runtime data and see they are different
        let runtime_data_1 = "nonce1".as_bytes();
        let evidence_request_1 = AttestationGetEvidenceRequest {
            runtime_data: runtime_data_1.to_vec(),
        };

        let runtime_data_2 = "nonce2".as_bytes();
        let evidence_request_2 = AttestationGetEvidenceRequest {
            runtime_data: runtime_data_2.to_vec(),
        };
        
        let kp = KeyManagerBuilder::build_mock().unwrap();
        let tee_service = TeeService::with_default_attestation(kp, None).await.unwrap();

        let res_1 = tee_service.get_attestation_evidence(evidence_request_1)
            .await
            .unwrap();
        let res_2 = tee_service.get_attestation_evidence(evidence_request_2)
            .await
            .unwrap();

        assert_ne!(res_1.evidence, res_2.evidence);
    }
    
    #[tokio::test]
    #[serial(attestation_agent)]
    async fn test_genesis_get_data_handler_success_basic() {
        // Initialize ATTESTATION_AGENT
        init_coco_aa().expect("Failed to initialize AttestationAgent");
        let kp = KeyManagerBuilder::build_mock().unwrap();

        // Call the handler
        let tee_service = TeeService::with_default_attestation(kp, None).await.unwrap();
        let res = tee_service.genesis_get_data_handler().await.unwrap();
        assert!(!res.evidence.is_empty());
    }

}
