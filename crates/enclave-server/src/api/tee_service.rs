use std::sync::Arc;

use log::error;
use jsonrpsee::core::{async_trait, RpcResult};
use seismic_enclave::coco_as::{ASCoreTokenClaims, AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse};
use seismic_enclave::genesis::GenesisDataResponse;

use crate::coco_as::{eval_att_evidence, parse_as_token_claims};
use crate::coco_as::into_original::{IntoOriginalData, OriginalData, OriginalHashAlgorithm, IntoOriginalHashAlgorithm};
use crate::key_manager::NetworkKeyProvider;
use crate::coco_aa::attest;
use seismic_enclave::coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse};
use crate::genesis::att_genesis_data;

use seismic_enclave::signing::{Secp256k1SignRequest, Secp256k1SignResponse};
use seismic_enclave::tx_io::{IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse};
use seismic_enclave::{ecdh_decrypt, ecdh_encrypt, rpc_bad_argument_error, rpc_bad_evidence_error, rpc_bad_genesis_error, rpc_bad_quote_error, rpc_invalid_ciphertext_error, secp256k1_sign_digest};

use super::seismic_attestation_agent::SeismicAttestationAgent;
use super::traits::TeeServiceApi;
use attestation_agent::AttestationAPIs;

// Unified service implementation
pub struct TeeService<K: NetworkKeyProvider> {
    key_provider: Arc<K>,
    attestation_agent: Arc<SeismicAttestationAgent>,
}

impl<K: NetworkKeyProvider> TeeService<K> {
    pub fn new(key_provider: Arc<K>, attestation_agent: Arc<SeismicAttestationAgent>) -> Self {
        Self { 
            key_provider,
            attestation_agent,
        }
    }

    // Factory method to create with default configuration
    pub async fn with_default_attestation(key_provider: K, config_path: Option<&str>) -> Result<Self, anyhow::Error> {
        let mut attestation_agent = SeismicAttestationAgent::new(config_path);
        
        attestation_agent.init().await?;
        
        Ok(Self::new(Arc::new(key_provider), Arc::new(attestation_agent)))
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
    use crate::{coco_aa::init_coco_aa, coco_as::{init_as_policies, init_coco_as, into_original::ApiData}, utils::test_utils::{is_sudo, read_vector_txt}};
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
    
    fn test_parse_as_token() {
        match env::current_dir() {
            Ok(path) => println!("Current directory: {}", path.display()),
            Err(e) => eprintln!("Error getting current directory: {}", e),
        }
        let ex_token_path = "../../examples/as_token.txt"; // assumes tests are run from enclaver-server dir
        let ex_token = std::fs::read_to_string(ex_token_path).unwrap();

        let claims = parse_as_token_claims(&ex_token).unwrap();

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

    #[tokio::test]
    #[serial(attestation_service)]
    async fn test_eval_evidence_sample() {
        // handle set up permissions
        if !is_sudo() {
            panic!("test_eval_evidence_sample: skipped (requires sudo privileges)");
        }

        // Initialize ATTESTATION_SERVICE
        init_coco_as(None)
            .await
            .expect("Failed to initialize AttestationService");

        // Mock a valid AttestationEvalEvidenceRequest
        let eval_request = AttestationEvalEvidenceRequest {
            evidence: vec![
                123, 34, 115, 118, 110, 34, 58, 34, 49, 34, 44, 34, 114, 101, 112, 111, 114, 116,
                95, 100, 97, 116, 97, 34, 58, 34, 98, 109, 57, 117, 89, 50, 85, 61, 34, 125,
            ], // Example evidence data
            tee: Tee::Sample,
            runtime_data: Some(Data::Raw("nonce".as_bytes().to_vec())), // Example runtime data
            runtime_data_hash_algorithm: Some(HashAlgorithm::Sha256),
            policy_ids: vec!["allow".to_string()],
        };

        let kp = KeyManagerBuilder::build_mock().unwrap();
        let tee_service = TeeService::with_default_attestation(kp, None).await.unwrap();
        
        // Call the handler
        let eval_evidence_response = tee_service.attestation_eval_evidence(eval_request)
            .await
            .unwrap();

        assert!(eval_evidence_response.eval);
        let claims = eval_evidence_response.claims.unwrap();
        assert_eq!(claims.tee, "sample");
        let tcb_status_map: serde_json::Map<String, Value> =
            serde_json::from_str(&claims.tcb_status).unwrap();
        assert_eq!(tcb_status_map["report_data"], "bm9uY2U=");
    }

    #[tokio::test]
    #[serial(attestation_service)]
    async fn test_eval_evidence_az_tdx() {
        // handle set up permissions
        if !is_sudo() {
            panic!("test_eval_evidence_az_tdx: skipped (requires sudo privileges)");
        }

        // Initialize ATTESTATION_SERVICE
        init_coco_as(None)
            .await
            .expect("Failed to initialize AttestationService");

        // Mock a valid AttestationEvalEvidenceRequest
        let tdx_evidence_encoded =
            std::fs::read_to_string("../../examples/tdx_encoded_evidence.txt").unwrap();
        let tdx_evidence = URL_SAFE_NO_PAD
            .decode(tdx_evidence_encoded.as_str())
            .unwrap();

        let tdx_eval_request = AttestationEvalEvidenceRequest {
            evidence: tdx_evidence,
            tee: Tee::AzTdxVtpm,
            runtime_data: Some(Data::Raw("".into())),
            runtime_data_hash_algorithm: None,
            policy_ids: vec!["allow".to_string()],
        };

        // Call the handler
        let kp = KeyManagerBuilder::build_mock().unwrap();
        let tee_service = TeeService::with_default_attestation(kp, None).await.unwrap();
        let eval_evidence_response = tee_service.attestation_eval_evidence(tdx_eval_request)
            .await
            .unwrap();

        assert!(eval_evidence_response.eval);
        let claims = eval_evidence_response.claims.unwrap();

        assert_eq!(claims.tee, "aztdxvtpm");
        let evaluation_reports = serde_json::to_string(&claims.evaluation_reports).unwrap();
        assert_eq!(evaluation_reports, "[{\"policy-hash\":\"fbb1cf91bb453d7c89b04cbc8d727dc142c47d84c5c9c2012b8c86d4d1892874743a63f7448e592ca6bee9cfeb286732\",\"policy-id\":\"allow\"}]");
        let tcb_status_map: serde_json::Map<String, Value> =
            serde_json::from_str(&claims.tcb_status).unwrap();
        assert_eq!(
            tcb_status_map.get("aztdxvtpm.quote.body.mr_td"),
            Some(&Value::String("bb379f8e734a755832509f61403f99db2258a70a01e1172a499d6d364101b0675455b4e372a35c1f006541f2de0d7154".to_string()))
        );
        assert_eq!(claims.customized_claims.init_data, Value::Null);
        assert_eq!(claims.customized_claims.runtime_data, Value::Null);
    }

    #[tokio::test]
    #[serial(attestation_service)]
    async fn test_eval_policy_deny() {
        // handle set up permissions
        if !is_sudo() {
            panic!("test_eval_evidence_az_tdx: skipped (requires sudo privileges)");
        }

        // Initialize ATTESTATION_SERVICE
        init_coco_as(None)
            .await
            .expect("Failed to initialize AttestationService");

        // Mock a valid AttestationEvalEvidenceRequest
        let eval_request = AttestationEvalEvidenceRequest {
            evidence: vec![
                123, 34, 115, 118, 110, 34, 58, 34, 49, 34, 44, 34, 114, 101, 112, 111, 114, 116,
                95, 100, 97, 116, 97, 34, 58, 34, 98, 109, 57, 117, 89, 50, 85, 61, 34, 125,
            ], // Example evidence data
            tee: Tee::Sample,
            runtime_data: Some(Data::Raw("nonce".as_bytes().to_vec())), // Example runtime data
            runtime_data_hash_algorithm: Some(HashAlgorithm::Sha256),
            policy_ids: vec!["deny".to_string()],
        };

        let kp = KeyManagerBuilder::build_mock().unwrap();
        let tee_service = TeeService::with_default_attestation(kp, None).await.unwrap();
        // Call the handler
        let eval_evidence_response = tee_service.attestation_eval_evidence(eval_request).await;

        assert!(
            eval_evidence_response.is_err(),
            "Expected error for deny policy {:?}",
            eval_evidence_response.err().unwrap()
        );
    }

    #[tokio::test]
    #[serial(attestation_service)]
    async fn test_eval_evidence_az_tdx_tpm_pcr04() {
        println!("starting test_eval_evidence_az_tdx_tpm_pcr04");
        // handle set up permissions
        if !is_sudo() {
            panic!("test_eval_evidence_az_tdx_tpm_pcr04: skipped (requires sudo privileges)");
        }

        init_coco_as(None)
            .await
            .expect("Failed to initialize AttestationService");

        // Make a passing request to validate using a policy that checks mr_td, mr_seam, and pcr04
        let az_tdx_evidence: Vec<u8> =
            read_vector_txt("../../examples/yocto_20241023223507.txt".to_string()).unwrap(); // assumes tests are run from enclaver-server dir
        let runtime_data_bytes = vec![
            240, 30, 194, 3, 67, 143, 162, 40, 249, 35, 238, 193, 59, 140, 203, 3, 98, 144, 105,
            221, 209, 34, 207, 229, 52, 61, 58, 14, 102, 234, 146, 8,
        ];
        let test_policy_id = "yocto".to_string();
        let tdx_eval_request = AttestationEvalEvidenceRequest {
            evidence: az_tdx_evidence,
            tee: Tee::AzTdxVtpm,
            runtime_data: Some(Data::Raw(runtime_data_bytes)),
            runtime_data_hash_algorithm: None,
            policy_ids: vec![test_policy_id.clone()],
        };

        let kp = KeyManagerBuilder::build_mock().unwrap();
        let tee_service = TeeService::with_default_attestation(kp, None).await.unwrap();
        let _eval_evidence_response = tee_service.attestation_eval_evidence(tdx_eval_request)
            .await
            .unwrap();

        // Make a failing request to validate using a policy that checks mr_td, mr_seam, and pcr04
        let az_tdx_evidence: Vec<u8> =
            read_vector_txt("../../examples/yocto_20241025193121.txt".to_string()).unwrap();
        let runtime_data_bytes = vec![
            240, 30, 194, 3, 67, 143, 162, 40, 249, 35, 238, 193, 59, 140, 203, 3, 98, 144, 105,
            221, 209, 34, 207, 229, 52, 61, 58, 14, 102, 234, 146, 8,
        ];
        let tdx_eval_request = AttestationEvalEvidenceRequest {
            evidence: az_tdx_evidence,
            tee: Tee::AzTdxVtpm,
            runtime_data: Some(Data::Raw(runtime_data_bytes)),
            runtime_data_hash_algorithm: None,
            policy_ids: vec!["yocto".to_string()],
        };
        let eval_evidence_response = tee_service.attestation_eval_evidence(tdx_eval_request).await;
        let expected_err_msg = format!("Reject by policy {test_policy_id}");
        let err_msg = eval_evidence_response.err().unwrap().to_string();
        assert!(
            err_msg.contains(&expected_err_msg),
            "Response does not contain expected message. Expected to see: \"{expected_err_msg}\", Was: {err_msg}"
        );
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

    #[tokio::test]
    #[serial(attestation_agent, attestation_service)]
    async fn test_genesis_get_data_handler_evidence_verifies() {
        // handle set up permissions
        if !is_sudo() {
            panic!("test_eval_evidence_az_tdx: skipped (requires sudo privileges)");
        }

        // Initialize ATTESTATION_AGENT and ATTESTATION_SERVICE
        init_coco_aa().expect("Failed to initialize AttestationAgent");
        init_coco_as(None)
            .await
            .expect("Failed to initialize AttestationService");
        init_as_policies()
            .await
            .expect("Failed to initialize AS policies");

        // Make a genesis data request
        let kp = KeyManagerBuilder::build_mock().unwrap();
        let tee_service = TeeService::with_default_attestation(kp, None).await.unwrap();
        let res = tee_service.genesis_get_data_handler().await.unwrap();

        // Submit the genesis data to the attestation service
        let bytes = res.data.to_bytes().unwrap();
        let genesis_data_hash: [u8; 32] = Sha256::digest(bytes).into();

        let tdx_eval_request = AttestationEvalEvidenceRequest {
            evidence: res.evidence,
            tee: Tee::AzTdxVtpm,
            runtime_data: Some(ApiData::Raw(genesis_data_hash.to_vec())), // Check that the genesis data hash matches the evidence report_data
            runtime_data_hash_algorithm: None,
            policy_ids: vec!["allow".to_string()],
        };
        let res = tee_service.attestation_eval_evidence(tdx_eval_request)
            .await
            .unwrap();

        assert!(res.eval);
    }
}
