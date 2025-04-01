use attestation_agent::AttestationAPIs;
use attestation_service::token::AttestationTokenBroker;
use attestation_service::{Data, HashAlgorithm};
use jsonrpsee::core::{async_trait, RpcResult};
use log::error;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use seismic_enclave::coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse};
use seismic_enclave::coco_as::ASCoreTokenClaims;
use seismic_enclave::coco_as::{AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse};
use seismic_enclave::genesis::{GenesisData, GenesisDataResponse};
use seismic_enclave::rpc::EnclaveApiServer;
use seismic_enclave::signing::{
    Secp256k1SignRequest, Secp256k1SignResponse, Secp256k1VerifyRequest, Secp256k1VerifyResponse,
};
use seismic_enclave::tx_io::{
    IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse,
};
use seismic_enclave::{
    ecdh_decrypt, ecdh_encrypt, rpc_bad_argument_error, rpc_bad_evidence_error,
    rpc_bad_genesis_error, rpc_bad_quote_error, rpc_invalid_ciphertext_error,
    secp256k1_sign_digest, secp256k1_verify,
};

use crate::attestation::SeismicAttestationAgent;
use crate::key_manager::NetworkKeyProvider;
use crate::server::into_original::IntoOriginalData;
use crate::server::into_original::IntoOriginalHashAlgorithm;

/// The main execution engine for secure enclave logic
/// handles server apu calls after http parsing and authentication
/// controls central resources, e.g. key manager, attestation agent
pub struct AttestationEngine<
    K: NetworkKeyProvider,
    T: AttestationTokenBroker + Send + Sync + 'static,
> {
    key_provider: Arc<K>,
    attestation_agent: Arc<SeismicAttestationAgent<T>>,
}
impl<K, T> AttestationEngine<K, T>
where
    K: NetworkKeyProvider + Send + Sync + 'static,
    T: AttestationTokenBroker + Send + Sync + 'static,
{
    pub fn new(key_provider: K, attestation_agent: SeismicAttestationAgent<T>) -> Self {
        Self {
            key_provider: Arc::new(key_provider),
            attestation_agent: Arc::new(attestation_agent),
        }
    }
}

#[async_trait]
impl<K, T> EnclaveApiServer for AttestationEngine<K, T>
where
    K: NetworkKeyProvider + Send + Sync + 'static,
    T: AttestationTokenBroker + Send + Sync + 'static,
{
    async fn health_check(&self) -> RpcResult<String> {
        Ok("OK".into())
    }

    // Crypto operations implementations
    async fn get_public_key(&self) -> RpcResult<secp256k1::PublicKey> {
        Ok(self.key_provider.get_tx_io_pk())
    }

    async fn sign(&self, req: Secp256k1SignRequest) -> RpcResult<Secp256k1SignResponse> {
        let sk = self.key_provider.get_tx_io_sk();
        let signature = secp256k1_sign_digest(&req.msg, sk)
            .map_err(|e| rpc_bad_argument_error(anyhow::anyhow!(e)))?;
        Ok(Secp256k1SignResponse { sig: signature })
    }

    async fn verify(&self, request: Secp256k1VerifyRequest) -> RpcResult<Secp256k1VerifyResponse> {
        let pk = self.key_provider.get_tx_io_pk();
        let verified = secp256k1_verify(&request.msg, &request.sig, pk)
            .map_err(|e| rpc_bad_argument_error(anyhow::anyhow!(e)))?;
        Ok(Secp256k1VerifyResponse { verified })
    }

    async fn encrypt(&self, req: IoEncryptionRequest) -> RpcResult<IoEncryptionResponse> {
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

    async fn decrypt(&self, req: IoDecryptionRequest) -> RpcResult<IoDecryptionResponse> {
        let sk = self.key_provider.get_tx_io_sk();
        let decrypted_data = match ecdh_decrypt(&req.key, &sk, &req.data, req.nonce) {
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

    // Attestation operations implementations
    async fn get_attestation_evidence(
        &self,
        req: AttestationGetEvidenceRequest,
    ) -> RpcResult<AttestationGetEvidenceResponse> {
        // Use SeismicAttestationAgent's mutex-protected get_evidence method
        // The mutex handling is already implemented in the agent
        let evidence = match self
            .attestation_agent
            .get_evidence(req.runtime_data.as_slice())
            .await
        {
            Ok(evidence) => evidence,
            Err(e) => {
                error!("Failed to get attestation evidence: {}", e);
                return Err(rpc_bad_quote_error(anyhow::anyhow!(
                    "Issue in getting the evidence"
                )));
            }
        };

        Ok(AttestationGetEvidenceResponse { evidence })
    }

    // Future Work: update what genesis data consists of, error responses
    async fn get_genesis_data(&self) -> RpcResult<GenesisDataResponse> {
        let io_pk = self.key_provider.get_tx_io_pk();

        // For now the genesis data is just the public key of the IO encryption keypair
        // But this is expected to change in the future
        let genesis_data = GenesisData { io_pk };

        // hash the genesis data and attest to it
        let genesis_data_bytes = match genesis_data.to_bytes() {
            Ok(bytes) => bytes,
            Err(e) => return Err(rpc_bad_genesis_error(anyhow::anyhow!(e))),
        };
        let hash_bytes: [u8; 32] = Sha256::digest(genesis_data_bytes).into();

        // Get the evidence from the attestation agent
        let evidence = match self
            .attestation_agent
            .get_evidence(&hash_bytes)
            .await
            .map_err(|e| format!("Error while getting evidence: {:?}", e))
        {
            Ok(evidence) => evidence,
            Err(e) => return Err(rpc_bad_quote_error(anyhow::anyhow!(e))),
        };

        Ok(GenesisDataResponse {
            data: genesis_data,
            evidence,
        })
    }

    async fn eval_attestation_evidence(
        &self,
        request: AttestationEvalEvidenceRequest,
    ) -> RpcResult<AttestationEvalEvidenceResponse> {
        // Convert the request's runtime data hash algorithm to the original enum
        let runtime_data: Option<Data> = request.runtime_data.map(|data| data.into_original());
        let runtime_data_hash_algorithm: HashAlgorithm = match request.runtime_data_hash_algorithm {
            Some(alg) => alg.into_original(),
            None => HashAlgorithm::Sha256,
        };

        // Evaluate attestation evidence (no lock needed for evaluation)
        let eval_result = self
            .attestation_agent
            .evaluate(
                request.evidence,
                request.tee,
                runtime_data,
                runtime_data_hash_algorithm,
                None,
                HashAlgorithm::Sha256,
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

        let claims: ASCoreTokenClaims = match ASCoreTokenClaims::from_jwt(&as_token) {
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
    use super::*;
    use crate::key_manager::KeyManager;
    use crate::key_manager::KeyManagerBuilder;
    use crate::utils::test_utils::is_sudo;
    use attestation_service::token::simple::SimpleAttestationTokenBroker;
    use seismic_enclave::{get_unsecure_sample_secp256k1_pk, nonce::Nonce};

    pub fn default_tee_service() -> AttestationEngine<KeyManager, SimpleAttestationTokenBroker> {
        let kp = KeyManagerBuilder::build_mock().unwrap();
        let v_token_broker = SimpleAttestationTokenBroker::new(
            attestation_service::token::simple::Configuration::default(),
        )
        .expect("Failed to create an AttestationAgent");
        let saa = SeismicAttestationAgent::new(None, v_token_broker);
        AttestationEngine::new(kp, saa)
    }

    #[tokio::test]
    pub async fn run_tests() {
        let tee_service: AttestationEngine<KeyManager, SimpleAttestationTokenBroker> =
            default_tee_service();

        let t1 = test_secp256k1_sign(&tee_service);
        let t2 = test_io_encryption(&tee_service);
        let t3 = test_decrypt_invalid_ciphertext(&tee_service);
        let t4 = test_attestation_evidence_handler_valid_request_sample(&tee_service);
        let t5 = test_attestation_evidence_handler_aztdxvtpm_runtime_data(&tee_service);
        let t6 = test_genesis_get_data_handler_success_basic(&tee_service);

        // Run all concurrently and await them
        let (_r1, _r2, _r3, _r4, _r5, _r6) = tokio::join!(t1, t2, t3, t4, t5, t6);
    }

    async fn test_secp256k1_sign<K, T>(tee_service: &AttestationEngine<K, T>)
    where
        K: NetworkKeyProvider + Send + Sync + 'static,
        T: AttestationTokenBroker + Send + Sync + 'static,
    {
        // Prepare sign request body
        let msg_to_sign: Vec<u8> = vec![84, 101, 115, 116, 32, 77, 101, 115, 115, 97, 103, 101]; // "Test Message"
        let sign_request = Secp256k1SignRequest {
            msg: msg_to_sign.clone(),
        };

        let res = tee_service.sign(sign_request).await.unwrap();

        // Prepare verify request body
        let verify_request = Secp256k1VerifyRequest {
            msg: msg_to_sign,
            sig: res.sig,
        };

        let res = tee_service.verify(verify_request).await.unwrap();
        assert!(res.verified);
    }

    async fn test_io_encryption<K, T>(tee_service: &AttestationEngine<K, T>)
    where
        K: NetworkKeyProvider + Send + Sync + 'static,
        T: AttestationTokenBroker + Send + Sync + 'static,
    {
        let data_to_encrypt = vec![72, 101, 108, 108, 111];
        let nonce = Nonce::new_rand();
        let req = IoEncryptionRequest {
            key: get_unsecure_sample_secp256k1_pk(),
            data: data_to_encrypt.clone(),
            nonce: nonce.clone(),
        };

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

    async fn test_decrypt_invalid_ciphertext<K, T>(tee_service: &AttestationEngine<K, T>)
    where
        K: NetworkKeyProvider + Send + Sync + 'static,
        T: AttestationTokenBroker + Send + Sync + 'static,
    {
        let bad_ciphertext = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let nonce = Nonce::new_rand();
        let decryption_request = IoDecryptionRequest {
            key: get_unsecure_sample_secp256k1_pk(),
            data: bad_ciphertext,
            nonce: nonce.clone(),
        };
        let res = tee_service.decrypt(decryption_request).await;

        assert!(res.is_err());
        assert!(
            res.err()
                .unwrap()
                .to_string()
                .contains("Invalid ciphertext")
        );
    }

    async fn test_attestation_evidence_handler_valid_request_sample<K, T>(
        tee_service: &AttestationEngine<K, T>,
    ) where
        K: NetworkKeyProvider + Send + Sync + 'static,
        T: AttestationTokenBroker + Send + Sync + 'static,
    {
        // Mock a valid AttestationGetEvidenceRequest
        let runtime_data = "nonce".as_bytes(); // Example runtime data
        let evidence_request = AttestationGetEvidenceRequest {
            runtime_data: runtime_data.to_vec(),
        };

        // Call the handler
        let res = tee_service
            .get_attestation_evidence(evidence_request)
            .await
            .unwrap();

        // Ensure the response is not empty
        assert!(!res.evidence.is_empty());
    }

    async fn test_attestation_evidence_handler_aztdxvtpm_runtime_data<K, T>(
        tee_service: &AttestationEngine<K, T>,
    ) where
        K: NetworkKeyProvider + Send + Sync + 'static,
        T: AttestationTokenBroker + Send + Sync + 'static,
    {
        // handle set up permissions
        if !is_sudo() {
            panic!("test_eval_evidence_az_tdx: skipped (requires sudo privileges)");
        }

        // Make requests with different runtime data and see they are different
        let runtime_data_1 = "nonce1".as_bytes();
        let evidence_request_1 = AttestationGetEvidenceRequest {
            runtime_data: runtime_data_1.to_vec(),
        };

        let runtime_data_2 = "nonce2".as_bytes();
        let evidence_request_2 = AttestationGetEvidenceRequest {
            runtime_data: runtime_data_2.to_vec(),
        };

        let res_1 = tee_service
            .get_attestation_evidence(evidence_request_1)
            .await
            .unwrap();
        let res_2 = tee_service
            .get_attestation_evidence(evidence_request_2)
            .await
            .unwrap();

        assert_ne!(res_1.evidence, res_2.evidence);
    }

    async fn test_genesis_get_data_handler_success_basic<K, T>(
        tee_service: &AttestationEngine<K, T>,
    ) where
        K: NetworkKeyProvider + Send + Sync + 'static,
        T: AttestationTokenBroker + Send + Sync + 'static,
    {
        // Call the handler
        let res = tee_service.get_genesis_data().await.unwrap();
        assert!(!res.evidence.is_empty());
    }
}
