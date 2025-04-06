use attestation_agent::AttestationAPIs;
use attestation_service::token::AttestationTokenBroker;
use attestation_service::{Data, HashAlgorithm};
use jsonrpsee::core::{async_trait, RpcResult};
use log::error;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use seismic_enclave::boot::{
    RetrieveMasterKeyRequest, RetrieveMasterKeyResponse, ShareMasterKeyRequest,
    ShareMasterKeyResponse,
};
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
    rpc_bad_genesis_error, rpc_bad_quote_error, rpc_internal_server_error,
    rpc_invalid_ciphertext_error, secp256k1_sign_digest, secp256k1_verify,
};

use crate::attestation::SeismicAttestationAgent;
use crate::key_manager::NetworkKeyProvider;
use crate::server::into_original::IntoOriginalData;
use crate::server::into_original::IntoOriginalHashAlgorithm;

use super::boot::Booter;

/// The main execution engine for secure enclave logic
/// handles server api calls after http parsing and authentication
/// controls central resources, e.g. key manager, attestation agent
pub struct AttestationEngine<
    K: NetworkKeyProvider + Send + Sync + 'static,
    T: AttestationTokenBroker + Send + Sync + 'static,
> {
    key_provider: Arc<K>,
    attestation_agent: Arc<SeismicAttestationAgent<T>>,
    booter: Arc<Booter>,
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
            booter: Arc::new(Booter::new()),
        }
    }

    pub fn key_provider(&self) -> Arc<K> {
        self.key_provider.clone()
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
        let key_provider = self.key_provider();
        Ok(key_provider.get_tx_io_pk())
    }

    async fn sign(&self, req: Secp256k1SignRequest) -> RpcResult<Secp256k1SignResponse> {
        let key_provider = self.key_provider();
        let sk = key_provider.get_tx_io_sk();
        let signature = secp256k1_sign_digest(&req.msg, sk)
            .map_err(|e| rpc_bad_argument_error(anyhow::anyhow!(e)))?;
        Ok(Secp256k1SignResponse { sig: signature })
    }

    async fn verify(&self, request: Secp256k1VerifyRequest) -> RpcResult<Secp256k1VerifyResponse> {
        let key_provider = self.key_provider();
        let pk = key_provider.get_tx_io_pk();
        let verified = secp256k1_verify(&request.msg, &request.sig, pk)
            .map_err(|e| rpc_bad_argument_error(anyhow::anyhow!(e)))?;
        Ok(Secp256k1VerifyResponse { verified })
    }

    async fn encrypt(&self, req: IoEncryptionRequest) -> RpcResult<IoEncryptionResponse> {
        let key_provider = self.key_provider();
        let sk = key_provider.get_tx_io_sk();
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
        let key_provider = self.key_provider();
        let sk = key_provider.get_tx_io_sk();
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
        let key_provider = self.key_provider();
        Ok(key_provider.get_rng_keypair())
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
        let key_provider = self.key_provider();
        let io_pk = key_provider.get_tx_io_pk();

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

    async fn boot_retrieve_root_key(
        &self,
        req: RetrieveMasterKeyRequest,
    ) -> RpcResult<RetrieveMasterKeyResponse> {
        // TODO: make attestation of retriever key
        let attestation: Vec<u8> = Vec::new();

        // TODO: create a client for the existing node
        use seismic_enclave::EnclaveClient;
        let client = EnclaveClient::mock(req.addr.ip().to_string(), req.addr.port()).unwrap();

        // Call the booter to retrieve the root key
        // will be stored in the booter if successful
        self.booter
            .retrieve_root_key(&attestation, &client)
            .map_err(
                |e| rpc_bad_argument_error(anyhow::anyhow!(e)), // TODO: better error
            )?;

        let resp = RetrieveMasterKeyResponse {};

        Ok(resp)
    }

    async fn boot_share_root_key(
        &self,
        req: ShareMasterKeyRequest,
    ) -> RpcResult<ShareMasterKeyResponse> {
        // TODO: verify the attestation of the retreiver key
        // TODO: make own attestation of sharer key
        let attestation: Vec<u8> = Vec::new();

        let key_provider = self.key_provider();
        let existing_km_root_key = key_provider.get_root_key();
        let (nonce, root_key_ciphertext, sharer_pk) = self
            .booter
            .share_root_key(&req.retriever_pk, &existing_km_root_key)
            .map_err(|e| rpc_bad_argument_error(anyhow::anyhow!(e)))?;

        Ok(ShareMasterKeyResponse {
            root_key_ciphertext,
            nonce,
            sharer_pk,
            attestation,
        })
    }

    async fn boot_genesis(&self) -> RpcResult<()> {
        self.booter
            .genesis()
            .map_err(|e| rpc_internal_server_error(e))?;
        Ok(())
    }

    async fn complete_boot(&self) -> RpcResult<()> {
        let root_key = match self.booter.get_root_key() {
            Some(root_key) => root_key,
            None => return Err(rpc_bad_genesis_error(anyhow::anyhow!("No root key found"))),
        };
        let km: Arc<K> = self.key_provider();
        km.set_root_key(root_key);

        // TODO: booter cleanup (mark complete somehow, boot functions error if already booted, other functions error if not booted)
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_manager::KeyManager;
    use crate::key_manager::KeyManagerBuilder;
    use crate::utils::test_utils::get_random_port;
    use crate::utils::test_utils::is_sudo;
    use attestation_service::token::simple::SimpleAttestationTokenBroker;
    use seismic_enclave::ENCLAVE_DEFAULT_ENDPOINT_IP;
    use seismic_enclave::{get_unsecure_sample_secp256k1_pk, nonce::Nonce};
    use serial_test::serial;
    use std::net::SocketAddr;

    pub fn default_enclave_engine() -> AttestationEngine<KeyManager, SimpleAttestationTokenBroker> {
        let kp = KeyManagerBuilder::build_mock().unwrap();
        let v_token_broker = SimpleAttestationTokenBroker::new(
            attestation_service::token::simple::Configuration::default(),
        )
        .expect("Failed to create an AttestationAgent");
        let saa = SeismicAttestationAgent::new(None, v_token_broker);
        AttestationEngine::new(kp, saa)
    }

    #[serial(attestation_agent)]
    #[tokio::test]
    pub async fn run_engine_tests() {
        let enclave_engine: AttestationEngine<KeyManager, SimpleAttestationTokenBroker> =
            default_enclave_engine();

        let t1 = test_secp256k1_sign(&enclave_engine);
        let t2 = test_io_encryption(&enclave_engine);
        let t3 = test_decrypt_invalid_ciphertext(&enclave_engine);
        let t4 = test_attestation_evidence_handler_valid_request_sample(&enclave_engine);
        let t5 = test_attestation_evidence_handler_aztdxvtpm_runtime_data(&enclave_engine);
        let t6 = test_genesis_get_data_handler_success_basic(&enclave_engine);
        let t7 = test_boot_handlers(&enclave_engine);

        // Run all concurrently and await them
        let (_r1, _r2, _r3, _r4, _r5, _r6, _r7) = tokio::join!(t1, t2, t3, t4, t5, t6, t7);
    }

    async fn test_secp256k1_sign<K, T>(enclave_engine: &AttestationEngine<K, T>)
    where
        K: NetworkKeyProvider + Send + Sync + 'static,
        T: AttestationTokenBroker + Send + Sync + 'static,
    {
        // Prepare sign request body
        let msg_to_sign: Vec<u8> = vec![84, 101, 115, 116, 32, 77, 101, 115, 115, 97, 103, 101]; // "Test Message"
        let sign_request = Secp256k1SignRequest {
            msg: msg_to_sign.clone(),
        };

        let res = enclave_engine.sign(sign_request).await.unwrap();

        // Prepare verify request body
        let verify_request = Secp256k1VerifyRequest {
            msg: msg_to_sign,
            sig: res.sig,
        };

        let res = enclave_engine.verify(verify_request).await.unwrap();
        assert!(res.verified);
    }

    async fn test_io_encryption<K, T>(enclave_engine: &AttestationEngine<K, T>)
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

        let res = enclave_engine.encrypt(req).await.unwrap();

        // check that decryption returns the original data
        // Prepare decrypt request body
        let req = IoDecryptionRequest {
            key: get_unsecure_sample_secp256k1_pk(),
            data: res.encrypted_data,
            nonce: nonce.clone(),
        };

        let res = enclave_engine.decrypt(req).await.unwrap();

        assert_eq!(res.decrypted_data, data_to_encrypt);
    }

    async fn test_decrypt_invalid_ciphertext<K, T>(enclave_engine: &AttestationEngine<K, T>)
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
        let res = enclave_engine.decrypt(decryption_request).await;

        assert!(res.is_err());
        assert!(res
            .err()
            .unwrap()
            .to_string()
            .contains("Invalid ciphertext"));
    }

    async fn test_attestation_evidence_handler_valid_request_sample<K, T>(
        enclave_engine: &AttestationEngine<K, T>,
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
        let res = enclave_engine
            .get_attestation_evidence(evidence_request)
            .await
            .unwrap();

        // Ensure the response is not empty
        assert!(!res.evidence.is_empty());
    }

    async fn test_attestation_evidence_handler_aztdxvtpm_runtime_data<K, T>(
        enclave_engine: &AttestationEngine<K, T>,
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

        let res_1 = enclave_engine
            .get_attestation_evidence(evidence_request_1)
            .await
            .unwrap();
        let res_2 = enclave_engine
            .get_attestation_evidence(evidence_request_2)
            .await
            .unwrap();

        assert_ne!(res_1.evidence, res_2.evidence);
    }

    async fn test_genesis_get_data_handler_success_basic<K, T>(
        enclave_engine: &AttestationEngine<K, T>,
    ) where
        K: NetworkKeyProvider + Send + Sync + 'static,
        T: AttestationTokenBroker + Send + Sync + 'static,
    {
        // Call the handler
        let res = enclave_engine.get_genesis_data().await.unwrap();
        assert!(!res.evidence.is_empty());
    }

    async fn test_boot_handlers<K, T>(enclave_engine: &AttestationEngine<K, T>)
    where
        K: NetworkKeyProvider + Send + Sync + 'static,
        T: AttestationTokenBroker + Send + Sync + 'static,
    {
        use seismic_enclave::rpc::BuildableServer;
        use seismic_enclave::MockEnclaveServer;

        // TODO: test boot_genesis
        // // test boot_genesis
        // enclave_engine.boot_genesis().await.unwrap();
        // let rand_root_key = enclave_engine.booter.get_root_key().unwrap();
        // assert!(rand_root_key != [0u8; 32], "root key genesis should be random");

        // test boot_retrieve_root_key against mock client
        let port = get_random_port();
        let addr = SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_IP, port));
        let mock_server = MockEnclaveServer::new(addr);
        mock_server.start().await.unwrap();
        enclave_engine
            .boot_retrieve_root_key(RetrieveMasterKeyRequest { addr })
            .await
            .unwrap();
        assert!(
            enclave_engine.booter.get_root_key().is_some(),
            "root key not set"
        );
        assert!(
            enclave_engine.booter.get_root_key().unwrap() == [0u8; 32],
            "root key does not match expected mock value"
        );

        // TODO: test share_root_key
        let new_node_booter = Booter::new();
        let resp = enclave_engine
            .boot_share_root_key(ShareMasterKeyRequest {
                retriever_pk: new_node_booter.pk(),
                attestation: Vec::new(),
            })
            .await
            .unwrap();
        let key_plaintext = new_node_booter.process_share_response(resp).unwrap();
        assert!(
            key_plaintext == [0u8; 32],
            "root key does not match expected mock value"
        );

        // TODO: test complete boot wiring
        enclave_engine.complete_boot().await.unwrap();
    }
}
