use crate::attestation::SeismicAttestationAgent;
use crate::key_manager::NetworkKeyProvider;
use crate::server::engine::AttestationEngine;

use seismic_enclave::coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse};
use seismic_enclave::coco_as::{AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse};
use seismic_enclave::genesis::GenesisDataResponse;
use seismic_enclave::rpc::{BuildableServer, EnclaveApiServer};
use seismic_enclave::signing::{
    Secp256k1SignRequest, Secp256k1SignResponse, Secp256k1VerifyRequest, Secp256k1VerifyResponse,
};
use seismic_enclave::tx_io::{
    IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse,
};
use seismic_enclave::{ENCLAVE_DEFAULT_ENDPOINT_IP, ENCLAVE_DEFAULT_ENDPOINT_PORT};

use anyhow::{anyhow, Result};
use attestation_service::token::simple::{
    Configuration as BrokerConfiguration, SimpleAttestationTokenBroker,
};
use attestation_service::token::AttestationTokenBroker;
use jsonrpsee::core::{async_trait, RpcResult};
use jsonrpsee::server::ServerHandle;
use jsonrpsee::Methods;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::{debug, info};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

/// The main server struct, with everything needed to run.
/// Can be constructed with the [`EnclaveServerBuilder`]
/// and started with the inherited [`start_rpc_server`] method
pub struct EnclaveServer<K, T>
where
    K: NetworkKeyProvider + Send + Sync + 'static,
    T: AttestationTokenBroker + Send + Sync + 'static,
{
    /// The address to listen on
    addr: SocketAddr,
    /// The main execution engine for secure enclave logic
    /// controls central resources, e.g. key manager, attestation agent
    inner: Arc<AttestationEngine<K, T>>,
}

/// A builder that lets us configure the server
pub struct EnclaveServerBuilder<K>
where
    K: NetworkKeyProvider + Send + Sync + 'static,
{
    addr: Option<SocketAddr>,
    key_provider: Option<K>,
    attestation_config_path: Option<String>,
    token_broker_config: Option<BrokerConfiguration>,
}
impl<K> Default for EnclaveServerBuilder<K>
where
    K: NetworkKeyProvider + Send + Sync + 'static,
{
    fn default() -> Self {
        Self {
            addr: Some(SocketAddr::new(
                ENCLAVE_DEFAULT_ENDPOINT_IP,
                ENCLAVE_DEFAULT_ENDPOINT_PORT,
            )),
            key_provider: None,
            attestation_config_path: None,
            token_broker_config: Some(BrokerConfiguration::default()),
        }
    }
}
impl<K> EnclaveServerBuilder<K>
where
    K: NetworkKeyProvider + Send + Sync + 'static,
{
    pub fn with_ip(mut self, ip: IpAddr) -> Self {
        if let Some(curr) = self.addr {
            self.addr = Some(SocketAddr::new(ip, curr.port()));
        } else {
            self.addr = Some(SocketAddr::new(ip, ENCLAVE_DEFAULT_ENDPOINT_PORT));
        }
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        if let Some(curr) = self.addr {
            self.addr = Some(SocketAddr::new(curr.ip(), port));
        } else {
            self.addr = Some(SocketAddr::new(ENCLAVE_DEFAULT_ENDPOINT_IP, port));
        }
        self
    }

    pub fn with_key_provider(mut self, key_provider: K) -> Self {
        self.key_provider = Some(key_provider);
        self
    }

    pub fn with_attestation_config(mut self, config_path: impl Into<String>) -> Self {
        self.attestation_config_path = Some(config_path.into());
        self
    }

    pub fn with_token_broker_config(mut self, config: BrokerConfiguration) -> Self {
        self.token_broker_config = Some(config);
        self
    }

    /// Build the final `EnclaveServer` object.
    /// Currently only support SimpleAttestationTokenBroker for the attestation verifier
    /// Because getting the types to compile is a pain
    pub async fn build(self) -> Result<EnclaveServer<K, SimpleAttestationTokenBroker>> {
        let final_addr = self.addr.ok_or_else(|| {
            anyhow!("No address found in builder (should not happen if default is set)")
        })?;
        let key_provider = self
            .key_provider
            .ok_or_else(|| anyhow!("No key provider supplied to builder"))?;
        let token_broker_config = self
            .token_broker_config
            .ok_or_else(|| anyhow!("No token broker config supplied to builder"))?;

        // Initialize AttestationEngine with the key provider
        let config_path = self.attestation_config_path.as_deref();
        let v_token_broker = SimpleAttestationTokenBroker::new(token_broker_config)?;
        let attestation_agent = SeismicAttestationAgent::new(config_path, v_token_broker);

        let inner = Arc::new(AttestationEngine::new(key_provider, attestation_agent));

        Ok(EnclaveServer {
            addr: final_addr,
            inner,
        })
    }
}

impl<K, T> EnclaveServer<K, T>
where
    K: NetworkKeyProvider + Send + Sync + 'static,
    T: AttestationTokenBroker + Send + Sync + 'static,
{
    /// Create a new builder with default address
    pub fn builder() -> EnclaveServerBuilder<K> {
        EnclaveServerBuilder::default()
    }

    /// Simplified constructor if you want to skip the builder
    pub async fn new(
        addr: impl Into<SocketAddr>,
        key_provider: K,
        token_broker: SeismicAttestationAgent<T>,
    ) -> Result<Self> {
        let inner = Arc::new(AttestationEngine::new(key_provider, token_broker));

        Ok(Self {
            addr: addr.into(),
            inner,
        })
    }
}
impl<K, T> BuildableServer for EnclaveServer<K, T>
where
    K: NetworkKeyProvider + Send + Sync + 'static,
    T: AttestationTokenBroker + Send + Sync + 'static,
{
    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn methods(self) -> Methods {
        self.into_rpc().into()
    }

    async fn start(self) -> Result<ServerHandle> {
        // No need for separate attestation init as AttestationEngine handles this
        let addr = self.addr.clone();
        let handle = BuildableServer::start_rpc_server(self).await;
        info!(target: "rpc::enclave", "Server started at {}", addr);
        handle
    }
}

#[async_trait]
impl<K, T> EnclaveApiServer for EnclaveServer<K, T>
where
    K: NetworkKeyProvider + Send + Sync + 'static,
    T: AttestationTokenBroker + Send + Sync + 'static,
{
    /// Handler for: `getPublicKey`
    async fn get_public_key(&self) -> RpcResult<secp256k1::PublicKey> {
        self.inner.get_public_key().await
    }

    /// Handler for: `healthCheck`
    async fn health_check(&self) -> RpcResult<String> {
        self.inner.health_check().await
    }

    /// Handler for: `getGenesisData`
    async fn get_genesis_data(&self) -> RpcResult<GenesisDataResponse> {
        debug!(target: "rpc::enclave", "Serving getGenesisData");
        self.inner.get_genesis_data().await
    }

    /// Handler for: `encrypt`
    async fn encrypt(&self, req: IoEncryptionRequest) -> RpcResult<IoEncryptionResponse> {
        debug!(target: "rpc::enclave", "Serving encrypt");
        self.inner.encrypt(req).await
    }

    /// Handler for: `decrypt`
    async fn decrypt(&self, req: IoDecryptionRequest) -> RpcResult<IoDecryptionResponse> {
        debug!(target: "rpc::enclave", "Serving decrypt");
        self.inner.decrypt(req).await
    }

    /// Handler for: `getAttestationEvidence`
    async fn get_attestation_evidence(
        &self,
        req: AttestationGetEvidenceRequest,
    ) -> RpcResult<AttestationGetEvidenceResponse> {
        debug!(target: "rpc::enclave", "Serving getAttestationEvidence");
        self.inner.get_attestation_evidence(req).await
    }

    /// Handler for: `evalAttestationEvidence`
    async fn eval_attestation_evidence(
        &self,
        req: AttestationEvalEvidenceRequest,
    ) -> RpcResult<AttestationEvalEvidenceResponse> {
        debug!(target: "rpc::enclave", "Serving evalAttestationEvidence");
        self.inner.eval_attestation_evidence(req).await
    }

    /// Handler for: `sign`
    async fn sign(&self, req: Secp256k1SignRequest) -> RpcResult<Secp256k1SignResponse> {
        debug!(target: "rpc::enclave", "Serving sign");
        self.inner.sign(req).await
    }

    /// Handler for: `verify`
    async fn verify(&self, req: Secp256k1VerifyRequest) -> RpcResult<Secp256k1VerifyResponse> {
        debug!(target: "rpc::enclave", "Serving verify");
        self.inner.verify(req).await
    }

    /// Handler for: 'eph_rng.get_keypair'
    async fn get_eph_rng_keypair(&self) -> RpcResult<schnorrkel::keys::Keypair> {
        debug!(target: "rpc::enclave", "Serving eph_rng.get_keypair");
        self.inner.get_eph_rng_keypair().await
    }
}

pub fn init_tracing() {
    // Read log level from RUST_LOG
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));

    // Initialize the subscriber
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter) // Use dynamic log level
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    info!("Enclave server tracing initialized");
}

#[cfg(test)]
mod tests {
    use crate::attestation::SeismicAttestationAgent;
    use crate::key_manager::{KeyManager, KeyManagerBuilder};
    use crate::server::{init_tracing, EnclaveServer};
    use crate::utils::test_utils::{get_random_port, is_sudo};
    use seismic_enclave::client::rpc::BuildableServer;
    use seismic_enclave::client::{
        EnclaveClient, EnclaveClientBuilder, ENCLAVE_DEFAULT_ENDPOINT_IP,
    };
    use seismic_enclave::coco_aa::AttestationGetEvidenceRequest;
    use seismic_enclave::coco_as::{AttestationEvalEvidenceRequest, Data, HashAlgorithm};
    use seismic_enclave::get_unsecure_sample_schnorrkel_keypair;
    use seismic_enclave::get_unsecure_sample_secp256k1_pk;
    use seismic_enclave::nonce::Nonce;
    use seismic_enclave::request_types::tx_io::*;
    use seismic_enclave::rpc::EnclaveApiClient;

    use attestation_service::token::simple::SimpleAttestationTokenBroker;
    use kbs_types::Tee;
    use serial_test::serial;
    use std::net::SocketAddr;
    use std::thread::sleep;
    use std::time::Duration;

    async fn test_tx_io_encrypt_decrypt(client: &EnclaveClient) {
        // make the request struct
        let data_to_encrypt = vec![72, 101, 108, 108, 111];
        let nonce = Nonce::new_rand();
        let encryption_request = IoEncryptionRequest {
            key: get_unsecure_sample_secp256k1_pk(),
            data: data_to_encrypt.clone(),
            nonce: nonce.clone(),
        };

        // make the http request
        let encryption_response = client.encrypt(encryption_request).await.unwrap();

        // check the response
        assert!(!encryption_response.encrypted_data.is_empty());

        let decryption_request = IoDecryptionRequest {
            key: get_unsecure_sample_secp256k1_pk(),
            data: encryption_response.encrypted_data,
            nonce: nonce.clone(),
        };

        let decryption_response = client.decrypt(decryption_request).await.unwrap();
        assert_eq!(decryption_response.decrypted_data, data_to_encrypt);
    }

    async fn test_health_check(client: &EnclaveClient) {
        let resposne = client.health_check().await.unwrap();
        assert_eq!(resposne, "OK");
    }

    async fn test_genesis_get_data(client: &EnclaveClient) {
        let resposne = client.get_genesis_data().await.unwrap();
        assert!(!resposne.evidence.is_empty());
    }

    async fn test_attestation_get_evidence(client: &EnclaveClient) {
        let runtime_data = "nonce".as_bytes(); // Example runtime data
        let evidence_request = AttestationGetEvidenceRequest {
            runtime_data: runtime_data.to_vec(),
        };

        // Call the handler
        let res = client
            .get_attestation_evidence(evidence_request)
            .await
            .unwrap();

        // Ensure the response is not empty
        assert!(!res.evidence.is_empty());
    }

    async fn test_attestation_eval_evidence(client: &EnclaveClient) {
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

        let resposne = client
            .eval_attestation_evidence(eval_request)
            .await
            .unwrap();

        assert!(resposne.eval);
    }

    async fn test_get_public_key(client: &EnclaveClient) {
        let res = client.get_public_key().await.unwrap();
        assert!(
            (res != get_unsecure_sample_secp256k1_pk()),
            "public key should be randomly generated"
        );
    }

    async fn test_get_eph_rng_keypair(client: &EnclaveClient) {
        let res: schnorrkel::Keypair = client.get_eph_rng_keypair().await.unwrap();
        assert!(
            !(res.secret == get_unsecure_sample_schnorrkel_keypair().secret),
            "eph rng keypair should be randomly generated"
        );
    }

    #[tokio::test]
    #[serial(attestation_agent)]
    async fn test_server_requests() {
        init_tracing();
        // handle set up permissions
        if !is_sudo() {
            tracing::error!("test_server_requests: skipped (requires sudo privileges)");
            return;
        }

        // spawn a seperate thread for the server, otherwise the test will hang
        let port = get_random_port(); // rand port for test parallelization
        let addr = SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_IP, port));
        let kp = KeyManagerBuilder::build_mock().unwrap();
        let token_broker = SimpleAttestationTokenBroker::new(
            attestation_service::token::simple::Configuration::default(),
        )
        .unwrap();
        let seismic_attestation_agent = SeismicAttestationAgent::new(None, token_broker);
        let _server_handle = EnclaveServer::<KeyManager, SimpleAttestationTokenBroker>::new(
            addr,
            kp,
            seismic_attestation_agent,
        )
        .await
        .unwrap()
        .start()
        .await
        .unwrap();
        sleep(Duration::from_secs(4));

        let client = EnclaveClientBuilder::new()
            .ip(ENCLAVE_DEFAULT_ENDPOINT_IP.to_string())
            .port(port)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        test_health_check(&client).await;
        test_genesis_get_data(&client).await;
        test_tx_io_encrypt_decrypt(&client).await;
        test_attestation_get_evidence(&client).await;
        test_attestation_eval_evidence(&client).await;
        test_get_public_key(&client).await;
        test_get_eph_rng_keypair(&client).await;
    }
}
