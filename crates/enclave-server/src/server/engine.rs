use attestation_agent::AttestationAPIs;
use attestation_service::HashAlgorithm;
use attestation_service::VerificationRequest;
use jsonrpsee::core::{async_trait, RpcResult};
use log::error;
use std::sync::Arc;

use super::boot::Booter;
use crate::attestation::seismic_aa_mock;
use crate::attestation::SeismicAttestationAgent;
use crate::key_manager::KeyManager;
use crate::key_manager::NetworkKeyProvider;
use crate::server::into_original::IntoOriginalData;
use crate::server::into_original::IntoOriginalHashAlgorithm;
use crate::utils::tdx_evidence_helpers::tdx_attestation_bytes_to_evidence_struct;
use seismic_enclave::request_types::*;
use seismic_enclave::rpc::EnclaveApiServer;
use seismic_enclave::EnclaveClient;
use seismic_enclave::{
    rpc_bad_argument_error, rpc_bad_evidence_error, rpc_bad_quote_error, rpc_conflict_error,
    rpc_internal_server_error,
};

/// The main execution engine for secure enclave logic
/// handles server api calls after http parsing and authentication
/// controls central resources, e.g. key manager, attestation agent
pub struct AttestationEngine<K: NetworkKeyProvider + Send + Sync + 'static> {
    key_provider: Arc<K>,
    attestation_agent: Arc<SeismicAttestationAgent>,
    booter: Arc<Booter>,
}
impl<K> AttestationEngine<K>
where
    K: NetworkKeyProvider + Send,
{
    pub fn new(key_provider: K, attestation_agent: SeismicAttestationAgent) -> Self {
        Self {
            key_provider: Arc::new(key_provider),
            attestation_agent: Arc::new(attestation_agent),
            booter: Arc::new(Booter::new()),
        }
    }

    /// helper function to get the key provider if it has been initialized
    /// or return an RPC uninitialized resource error
    pub fn key_provider(&self) -> Result<Arc<K>, jsonrpsee::types::ErrorObjectOwned> {
        if !self.booter.is_compelted() {
            return Err(rpc_conflict_error(anyhow::anyhow!(
                "Key provider not initialized"
            )));
        } else {
            return Ok(self.key_provider.clone());
        }
    }
}

#[async_trait]
impl<K> EnclaveApiServer for AttestationEngine<K>
where
    K: NetworkKeyProvider + Send + Sync + 'static,
{
    async fn health_check(&self) -> RpcResult<String> {
        Ok("OK".into())
    }

    async fn get_purpose_keys(
        &self,
        req: GetPurposeKeysRequest,
    ) -> RpcResult<GetPurposeKeysResponse> {
        let key_provider = self.key_provider()?;
        let epoch = req.epoch;
        let resp = GetPurposeKeysResponse {
            tx_io_sk: key_provider.get_tx_io_sk(epoch),
            tx_io_pk: key_provider.get_tx_io_pk(epoch),
            snapshot_key_bytes: key_provider.get_snapshot_key(epoch).into(),
            rng_keypair: key_provider.get_rng_keypair(epoch),
        };
        Ok(resp)
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

    /// Evaluate the provided attestation evidence against a policy
    /// and return the claims if the evidence is valid
    /// Returns a rpc_bad_argument repsonse if the evidence is invalid or doens't match the provided policy
    async fn eval_attestation_evidence(
        &self,
        request: AttestationEvalEvidenceRequest,
    ) -> RpcResult<AttestationEvalEvidenceResponse> {
        // Convert the request's runtime data hash algorithm to the original enum
        let runtime_data: Option<attestation_service::Data> =
            request.runtime_data.map(|data| data.into_original());
        let runtime_data_hash_algorithm: attestation_service::HashAlgorithm =
            match request.runtime_data_hash_algorithm {
                Some(alg) => alg.into_original(),
                None => attestation_service::HashAlgorithm::Sha256,
            };

        // Convert bytes to Evidence struct
        // TODO: change AttestationEvalEvidenceRequest so this step is not needed?
        // Note: these lines restrict evidence to be azure-tdx specific
        let evidence = tdx_attestation_bytes_to_evidence_struct(&request.evidence).unwrap();
        let evidence: attestation_service::TeeEvidence = serde_json::to_value(evidence).unwrap();

        // Evaluate attestation evidence (no lock needed for evaluation)
        let verification_request = VerificationRequest {
            evidence: evidence,
            tee: request.tee,
            runtime_data,
            runtime_data_hash_algorithm,
            init_data: None,
            init_data_hash_algorithm: HashAlgorithm::Sha256,
        };
        let eval_result = self
            .attestation_agent
            .evaluate(vec![verification_request], request.policy_ids)
            .await;

        // Retrieve the claims from the AS token
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
                return Err(rpc_internal_server_error(anyhow::anyhow!(
                    "Attestation evaluation passed, but encountered error while parsing AS token: {e}"
                )));
            }
        };

        Ok(AttestationEvalEvidenceResponse {
            claims: Some(claims),
        })
    }

    /// Retrieves the network root key from an existing node
    /// and updates this node's booter root key
    /// Operator is expected to call complete_boot after this
    async fn boot_retrieve_root_key(
        &self,
        req: RetrieveRootKeyRequest,
    ) -> RpcResult<RetrieveRootKeyResponse> {
        if self.key_provider().is_ok() {
            return Err(rpc_conflict_error(anyhow::anyhow!(
                "Key provider already initialized"
            )));
        }

        let tee = self.attestation_agent.get_tee_type();
        let retriver_pk_bytes = self.booter.pk().serialize();
        let attestation: Vec<u8> = self
            .attestation_agent
            .get_evidence(&retriver_pk_bytes)
            .await
            .map_err(|e| rpc_internal_server_error(e))?;

        let client_builder = EnclaveClient::builder();
        let client = client_builder
            .ip(req.addr.ip().to_string())
            .port(req.addr.port())
            .build()
            .unwrap();

        // Call the booter to retrieve the root key
        // will be stored in the booter if successful
        self.booter
            .retrieve_root_key(tee, &attestation, &client)
            .map_err(|e| rpc_bad_argument_error(anyhow::anyhow!(e)))?;

        let resp = RetrieveRootKeyResponse {};

        Ok(resp)
    }

    /// Endpoint for requesting the network's root key from an existing node
    /// Checks the the new node is authorized to retrieve the root key and
    /// encrypts the existing root key for the new node
    async fn boot_share_root_key(
        &self,
        req: ShareRootKeyRequest,
    ) -> RpcResult<ShareRootKeyResponse> {
        // FUTURE WORK: make sure the "share_root" policy is up to date with on-chain votes

        // Verify new enclave's attestation
        let _ = self.eval_attestation_evidence(req.clone().into()).await?;

        // Encrypt the existing root key
        let key_provider = self.key_provider()?;
        let existing_km_root_key = key_provider.get_root_key();
        let (nonce, root_key_ciphertext, sharer_pk) = self
            .booter
            .encrypt_root_key(&req.retriever_pk, &existing_km_root_key)
            .map_err(|e| rpc_bad_argument_error(anyhow::anyhow!(e)))?;

        // return relevant response
        Ok(ShareRootKeyResponse {
            root_key_ciphertext,
            nonce,
            sharer_pk,
        })
    }

    /// Endpoint for generating a new genesis network root key
    /// User is expected to call complete_boot after this
    async fn boot_genesis(&self) -> RpcResult<()> {
        if self.key_provider().is_ok() {
            return Err(rpc_conflict_error(anyhow::anyhow!(
                "Key provider already initialized"
            )));
        }
        self.booter
            .genesis()
            .map_err(|e| rpc_internal_server_error(e))?;
        Ok(())
    }

    /// Completes the booting process by setting the key manager
    async fn complete_boot(&self) -> RpcResult<()> {
        if self.key_provider().is_ok() {
            return Err(rpc_conflict_error(anyhow::anyhow!(
                "Key provider already initialized"
            )));
        }
        let root_key = match self.booter.get_root_key() {
            Some(root_key) => root_key,
            None => return Err(rpc_conflict_error(anyhow::anyhow!("Booter has not initialized a root key. Either call boot_retrieve_root_key or boot_genesis first"))),
        };
        let existing_km = self.key_provider.clone();
        existing_km.set_root_key(root_key);
        self.booter.mark_completed();

        Ok(())
    }

    async fn prepare_encrypted_snapshot(&self, req: PrepareEncryptedSnapshotRequest) -> RpcResult<PrepareEncryptedSnapshotResponse> {
        unimplemented!("prepare_encrypted_snapshot not implemented")
    }
    async fn restore_from_encrypted_snapshot(&self, req: RestoreFromEncryptedSnapshotRequest) -> RpcResult<RestoreFromEncryptedSnapshotResponse> {
        unimplemented!("restore_from_encrypted_snapshot not implemented")
    }
}

#[allow(dead_code)]
pub async fn engine_mock_booted() -> AttestationEngine<KeyManager> {
    let kp = KeyManager::new([0u8; 32]);
    kp.set_root_key([0u8; 32]);
    let saa = seismic_aa_mock().await;
    let mut enclave_engine = AttestationEngine::new(kp, saa);
    enclave_engine.booter = Booter::mock().into();
    enclave_engine.booter.mark_completed();
    enclave_engine
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_manager::KeyManagerBuilder;
    use crate::utils::test_utils::get_random_port;
    use crate::utils::test_utils::is_sudo;
    use crate::utils::test_utils::pub_key_eval_request;
    use seismic_enclave::get_unsecure_sample_secp256k1_pk;
    use seismic_enclave::rpc::BuildableServer;
    use seismic_enclave::MockEnclaveServer;
    use seismic_enclave::ENCLAVE_DEFAULT_ENDPOINT_IP;
    use serial_test::serial;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::time::sleep;

    pub async fn default_unbooted_enclave_engine() -> AttestationEngine<KeyManager> {
        let kp = KeyManagerBuilder::build_mock().unwrap();
        let saa = seismic_aa_mock().await;
        AttestationEngine::new(kp, saa)
    }

    #[serial(attestation_agent)]
    #[tokio::test]
    pub async fn run_engine_tests() {
        if !is_sudo() {
            panic!("run_engine_tests: skipped (requires sudo privileges)");
        }

        let enclave_engine: AttestationEngine<KeyManager> = engine_mock_booted().await;

        let t1 = test_attestation_evidence_handler_valid_request_sample(&enclave_engine);
        let t2 = test_attestation_evidence_handler_aztdxvtpm_runtime_data(&enclave_engine);
        let t3 = test_get_purpose_keys(&enclave_engine);

        // Run all concurrently and await them
        let (_r1, _r2, _r3) = tokio::join!(t1, t2, t3);
    }

    async fn test_attestation_evidence_handler_valid_request_sample<K>(
        enclave_engine: &AttestationEngine<K>,
    ) where
        K: NetworkKeyProvider + Send + Sync + 'static,
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

    async fn test_attestation_evidence_handler_aztdxvtpm_runtime_data<K>(
        enclave_engine: &AttestationEngine<K>,
    ) where
        K: NetworkKeyProvider + Send + Sync + 'static,
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

    async fn test_get_purpose_keys<K>(enclave_engine: &AttestationEngine<K>)
    where
        K: NetworkKeyProvider + Send + Sync + 'static,
    {
        let epoch = 0;
        let res = enclave_engine
            .get_purpose_keys(GetPurposeKeysRequest { epoch: epoch })
            .await;
        assert!(res.is_ok());
        let resp = res.unwrap();

        let kp = enclave_engine.key_provider().unwrap();
        assert_eq!(resp.tx_io_pk, kp.get_tx_io_pk(epoch));
        assert_eq!(resp.tx_io_sk, kp.get_tx_io_sk(epoch));
        assert_eq!(resp.rng_keypair.secret, kp.get_rng_keypair(epoch).secret);
        assert_eq!(
            resp.snapshot_key_bytes,
            Into::<[u8; 32]>::into(kp.get_snapshot_key(epoch))
        );
    }

    #[serial(attestation_agent)]
    #[tokio::test]
    async fn test_boot_share_root_key() {
        if !is_sudo() {
            panic!("test_boot_share_root_key: skipped (requires sudo privileges)");
        }

        let enclave_engine: AttestationEngine<KeyManager> = engine_mock_booted().await;

        let new_node_booter = Booter::mock();
        let eval_context: AttestationEvalEvidenceRequest = pub_key_eval_request();
        assert_eq!(
            seismic_enclave::request_types::Data::Raw(new_node_booter.pk().serialize().to_vec()),
            eval_context.clone().runtime_data.unwrap(),
            "test misconfigured, attestation should be of the new booter's public key"
        );
        let resp = enclave_engine
            .boot_share_root_key(ShareRootKeyRequest {
                evidence: eval_context.evidence,
                tee: eval_context.tee,
                retriever_pk: new_node_booter.pk(),
            })
            .await
            .unwrap();
        let key_plaintext = new_node_booter.process_share_response(resp).unwrap(); // erroring due to mismatch
        assert!(
            key_plaintext == [0u8; 32],
            "root key does not match expected mock value"
        );
    }

    #[serial(attestation_agent)]
    #[tokio::test]
    async fn test_complete_boot() -> Result<(), anyhow::Error> {
        if !is_sudo() {
            panic!("test_complete_boot: skipped (requires sudo privileges)");
        }
        let enclave_engine: AttestationEngine<KeyManager> = default_unbooted_enclave_engine().await;

        let eval_context = pub_key_eval_request();

        let mock_addr = SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_IP, 0));
        let mock_share_req = ShareRootKeyRequest {
            evidence: eval_context.evidence,
            tee: eval_context.tee,
            retriever_pk: get_unsecure_sample_secp256k1_pk(),
        };

        // test that key functions error before complete_boot
        let res = enclave_engine
            .get_purpose_keys(GetPurposeKeysRequest { epoch: 0 })
            .await;
        assert!(res.is_err());
        let res = enclave_engine
            .boot_share_root_key(mock_share_req.clone())
            .await;
        assert!(res.is_err());

        // test that complete_boot works
        enclave_engine.boot_genesis().await.unwrap();
        enclave_engine.complete_boot().await.unwrap();
        assert!(
            enclave_engine.booter.is_compelted(),
            "booting should be marked complete"
        );

        // test that key functions work after complete_boot
        let _ = enclave_engine
            .get_purpose_keys(GetPurposeKeysRequest { epoch: 0 })
            .await?;
        let _ = enclave_engine
            .boot_share_root_key(mock_share_req.clone())
            .await?;

        // test that boot functions error after complete_boot
        let res = enclave_engine.boot_genesis().await;
        assert!(
            res.is_err(),
            "boot_genesis should return error after complete_boot"
        );

        let policy = "share_root".to_string();
        let res = enclave_engine
            .boot_retrieve_root_key(RetrieveRootKeyRequest {
                addr: mock_addr,
                attestation_policy_id: policy,
            })
            .await;
        assert!(
            res.is_err(),
            "boot_retrieve_root_key should return error after complete_boot"
        );
        let res = enclave_engine.complete_boot().await;
        assert!(
            res.is_err(),
            "complete_boot should return error after complete_boot"
        );

        Ok(())
    }

    #[serial(attestation_agent)]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_boot_retrieve_root_key() -> Result<(), anyhow::Error> {
        if !is_sudo() {
            panic!("test_boot_retrieve_root_key: skipped (requires sudo privileges)");
        }
        let enclave_engine: AttestationEngine<KeyManager> = default_unbooted_enclave_engine().await;

        // assert the booter root key begins uninitialized
        assert!(enclave_engine.booter.get_root_key().is_none());

        // start a mock server
        let port = get_random_port();
        let addr = SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_IP, port));
        let _server_handle = MockEnclaveServer::new(addr.clone()).start().await?;
        let _ = sleep(Duration::from_secs(2)).await;

        // run the request
        let _ = enclave_engine
            .boot_retrieve_root_key(RetrieveRootKeyRequest {
                addr,
                attestation_policy_id: "share_root".to_string(),
            })
            .await?;

        // check that the root key is now initialized to the mock value
        assert_eq!(enclave_engine.booter.get_root_key().unwrap(), [0u8; 32]);

        Ok(())
    }
}
