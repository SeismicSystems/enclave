use crate::api::{AttestationEngineApi, AttestationEngine};
use crate::key_manager::NetworkKeyProvider;
use crate::attestation::agent::SeismicAttestationAgent;

use seismic_enclave::coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse};
use seismic_enclave::coco_as::{AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse};
use seismic_enclave::genesis::GenesisDataResponse;
use seismic_enclave::rpc::{BuildableServer, EnclaveApiServer};
use seismic_enclave::signing::{
    Secp256k1SignRequest, Secp256k1SignResponse,
};
use seismic_enclave::tx_io::{
    IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse,
};
use seismic_enclave::{ENCLAVE_DEFAULT_ENDPOINT_ADDR, ENCLAVE_DEFAULT_ENDPOINT_PORT};
use seismic_enclave::auth::JwtSecret;

use anyhow::{anyhow, Result};
use attestation_service::token::AttestationTokenBroker;
use jsonrpsee::core::{async_trait, RpcResult};
use jsonrpsee::server::ServerHandle;
use jsonrpsee::Methods;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::{debug, info};
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use attestation_service::token::simple::{SimpleAttestationTokenBroker, Configuration as BrokerConfiguration};

/// The main server struct, with everything needed to run.
pub struct EnclaveServer<K, T>
where
    K: NetworkKeyProvider + Send + Sync + 'static,
    T: AttestationTokenBroker + Send + Sync + 'static,
{
    /// The address to listen on
    addr: SocketAddr,
    /// The JWT authentication secret for http requests
    /// Expected to also be known by the client sending requests
    auth_secret: JwtSecret,
    /// The main execution engine for secure enclave logic
    /// controls central resources, e.g. key manager, attestation agent
    tee_service: Arc<AttestationEngine<K, T>>,
}

/// A builder that lets us configure the server
pub struct EnclaveServerBuilder<K>
where
    K: NetworkKeyProvider + Send + Sync + 'static,
{
    addr: Option<SocketAddr>,
    auth_secret: Option<JwtSecret>,
    key_provider: Option<K>,
    attestation_config_path: Option<String>,
}
impl<K> Default for EnclaveServerBuilder<K>
where
    K: NetworkKeyProvider + Send + Sync + 'static,
{
    fn default() -> Self {
        Self {
            addr: Some(SocketAddr::new(
                ENCLAVE_DEFAULT_ENDPOINT_ADDR,
                ENCLAVE_DEFAULT_ENDPOINT_PORT,
            )),
            auth_secret: None,
            key_provider: None,
            attestation_config_path: None,
        }
    }
}

impl<K> EnclaveServerBuilder<K>
where
    K: NetworkKeyProvider + Send + Sync + 'static,
{
    pub fn with_addr(mut self, ip_addr: IpAddr) -> Self {
        if let Some(curr) = self.addr {
            self.addr = Some(SocketAddr::new(ip_addr, curr.port()));
        } else {
            self.addr = Some(SocketAddr::new(ip_addr, ENCLAVE_DEFAULT_ENDPOINT_PORT));
        }
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        if let Some(curr) = self.addr {
            self.addr = Some(SocketAddr::new(curr.ip(), port));
        } else {
            self.addr = Some(SocketAddr::new(ENCLAVE_DEFAULT_ENDPOINT_ADDR, port));
        }
        self
    }

    pub fn with_auth_secret(mut self, auth_secret: JwtSecret) -> Self {
        self.auth_secret = Some(auth_secret);
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

    /// Build the final `EnclaveServer` object.
    /// Currently only support SimpleAttestationTokenBroker for the attestation verifier 
    /// Because getting the types to compile is a pain
    /// TODO: allow builder to have a BrokerConfiguration passed in
    pub async fn build(self) -> Result<EnclaveServer<K, SimpleAttestationTokenBroker>> {
        let final_addr = self.addr.ok_or_else(|| {
            anyhow!("No address found in builder (should not happen if default is set)")
        })?;

        let key_provider = self.key_provider.ok_or_else(|| {
            anyhow!("No key provider supplied to builder")
        })?;

        let auth_secret = self.auth_secret.ok_or_else(|| {
            anyhow!("No auth secret supplied to builder")
        })?;
       
        // Initialize AttestationEngine with the key provider
        let config_path = self.attestation_config_path.as_deref();
        let v_token_broker = SimpleAttestationTokenBroker::new(BrokerConfiguration::default())?;
        let attestation_agent = SeismicAttestationAgent::new(config_path, v_token_broker);

        let tee_service = Arc::new(
            AttestationEngine::new(key_provider, attestation_agent)
        );

        Ok(EnclaveServer {
            addr: final_addr,
            auth_secret,
            tee_service,
        })
    }
}

impl<K, T>EnclaveServer<K, T>
where
    K: NetworkKeyProvider + Send + Sync + 'static,
    T: AttestationTokenBroker + Send + Sync + 'static,
{
    /// Create a new builder with default address
    pub fn builder() -> EnclaveServerBuilder<K> {
        EnclaveServerBuilder::default()
    }
    
    /// Simplified constructor if you want to skip the builder
    pub async fn new(addr: impl Into<SocketAddr>, key_provider: K, token_broker: crate::attestation::agent::SeismicAttestationAgent<T>, auth_secret: JwtSecret) -> Result<Self> {
         let tee_service = Arc::new(
             AttestationEngine::new(key_provider, token_broker)
         );
        
         Ok(Self {
             addr: addr.into(),
             tee_service,
             auth_secret,
         })
    }
}
impl<K, T>BuildableServer for EnclaveServer<K, T>
where
    K: NetworkKeyProvider + Send + Sync + 'static,
    T: AttestationTokenBroker + Send + Sync + 'static,
{
    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn auth_secret(&self) -> JwtSecret {
        self.auth_secret
    }

    fn methods(self) -> Methods {
        self.into_rpc().into()
    }

    async fn start(self) -> Result<ServerHandle> {
        // No need for separate attestation init as AttestationEngine handles this
        BuildableServer::start_rpc_server(self).await
    }
}

#[async_trait]
impl<K, T>EnclaveApiServer for EnclaveServer<K, T>
where
    K: NetworkKeyProvider + Send + Sync + 'static,
    T: AttestationTokenBroker + Send + Sync + 'static,
{
    /// Handler for: `getPublicKey`
    async fn get_public_key(&self) -> RpcResult<secp256k1::PublicKey> {
        self.tee_service.get_public_key().await
    }

    /// Handler for: `healthCheck`
    async fn health_check(&self) -> RpcResult<String> {
        Ok("OK".into())
    }

    /// Handler for: `getGenesisData`
    async fn get_genesis_data(&self) -> RpcResult<GenesisDataResponse> {
        debug!(target: "rpc::enclave", "Serving getGenesisData");
        self.tee_service.genesis_get_data_handler().await
    }

    /// Handler for: `encrypt`
    async fn encrypt(&self, req: IoEncryptionRequest) -> RpcResult<IoEncryptionResponse> {
        debug!(target: "rpc::enclave", "Serving encrypt");
        self.tee_service.encrypt(req).await
    }

    /// Handler for: `decrypt`
    async fn decrypt(&self, req: IoDecryptionRequest) -> RpcResult<IoDecryptionResponse> {
        debug!(target: "rpc::enclave", "Serving decrypt");
        self.tee_service.decrypt(req).await
    }

    /// Handler for: `getAttestationEvidence`
    async fn get_attestation_evidence(
        &self,
        req: AttestationGetEvidenceRequest,
    ) -> RpcResult<AttestationGetEvidenceResponse> {
        debug!(target: "rpc::enclave", "Serving getAttestationEvidence");
        self.tee_service.get_attestation_evidence(req).await
    }

    /// Handler for: `evalAttestationEvidence`
    async fn eval_attestation_evidence(
        &self,
        req: AttestationEvalEvidenceRequest,
    ) -> RpcResult<AttestationEvalEvidenceResponse> {
        debug!(target: "rpc::enclave", "Serving evalAttestationEvidence");
        self.tee_service.attestation_eval_evidence(req).await
    }

    /// Handler for: `sign`
    async fn sign(&self, req: Secp256k1SignRequest) -> RpcResult<Secp256k1SignResponse> {
        debug!(target: "rpc::enclave", "Serving sign");
        self.tee_service.secp256k1_sign(req).await
    }

    /// Handler for: 'eph_rng.get_keypair'
    async fn get_eph_rng_keypair(&self) -> RpcResult<schnorrkel::keys::Keypair> {
        debug!(target: "rpc::enclave", "Serving eph_rng.get_keypair");
        self.tee_service.get_eph_rng_keypair().await
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
