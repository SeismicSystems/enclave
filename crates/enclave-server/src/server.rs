use crate::api::traits::TeeServiceApi;
use crate::api::tee_service::TeeService;
use crate::coco_aa::init_coco_aa;
use crate::coco_as::init_coco_as;
use crate::key_manager::builder::KeyManagerBuilder;
use crate::key_manager::key_manager::KeyManager;
use crate::key_manager::NetworkKeyProvider;

use anyhow::{anyhow, Result};
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

use jsonrpsee::core::{async_trait, RpcResult};
use jsonrpsee::server::ServerHandle;
use jsonrpsee::Methods;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, info};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use jsonrpsee::server::ServerBuilder;
use reth_rpc_layer::{AuthLayer, JwtAuthValidator, JwtSecret};

/// The main server struct, with everything needed to run.
pub struct EnclaveServer<K: NetworkKeyProvider + Send + Sync + 'static> {
    addr: SocketAddr,
    auth_secret: Option<JwtSecret>,
    tee_service: Arc<TeeService<K>>,
}

/// A builder that lets us configure the server
pub struct EnclaveServerBuilder<K: NetworkKeyProvider + Send + Sync + 'static> {
    addr: Option<SocketAddr>,
    auth_secret: Option<JwtSecret>,
    key_provider: Option<K>,
    attestation_config_path: Option<String>,
}

impl<K: NetworkKeyProvider + Send + Sync + 'static> Default for EnclaveServerBuilder<K> {
    fn default() -> Self {
        Self {
            addr: Some(SocketAddr::new(
                ENCLAVE_DEFAULT_ENDPOINT_ADDR,
                ENCLAVE_DEFAULT_ENDPOINT_PORT,
            )),
            key_provider: None,
            attestation_config_path: None,
            auth_secret: None,
        }
    }
}

impl<K: NetworkKeyProvider + Send + Sync + 'static> EnclaveServerBuilder<K> {
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

    pub fn with_key_provider(mut self, key_provider: K) -> Self {
        self.key_provider = Some(key_provider);
        self
    }

    pub fn with_attestation_config(mut self, config_path: impl Into<String>) -> Self {
        self.attestation_config_path = Some(config_path.into());
        self
    }

    pub fn with_auth_secret(mut self, secret: JwtSecret) -> Self {
        self.auth_secret = Some(secret);
        self
    }

    /// Build the final `EnclaveServer` object.
    pub async fn build(self) -> Result<EnclaveServer<K>> {
        let final_addr = self.addr.ok_or_else(|| {
            anyhow!("No address found in builder (should not happen if default is set)")
        })?;

        let key_provider = self.key_provider.ok_or_else(|| {
            anyhow!("No key provider supplied to builder")
        })?;
       
        // Initialize TeeService with the key provider
        let config_path = self.attestation_config_path.as_deref();
        let tee_service = Arc::new(
            TeeService::with_default_attestation(key_provider, config_path)
                .await
                .map_err(|e| anyhow!("Failed to initialize TeeService: {}", e))?,
        );

        Ok(EnclaveServer {
            addr: final_addr,
            auth_secret: self.auth_secret,
            tee_service,
        })
    }
}


impl<K: NetworkKeyProvider + Send + Sync + 'static> EnclaveServer<K> {
    /// Create a new builder with default address
    pub fn builder() -> EnclaveServerBuilder<K> {
        EnclaveServerBuilder::default()
    }
    
    /// Simplified constructor if you want to skip the builder
    pub async fn new(addr: impl Into<SocketAddr>, key_provider: K, auth_secret: Option<JwtSecret>) -> Result<Self> {
        let tee_service = Arc::new(
            TeeService::with_default_attestation(key_provider, None)
                .await
                .map_err(|e| anyhow!("Failed to initialize TeeService: {}", e))?,
        );
        
        Ok(Self {
            addr: addr.into(),
            auth_secret,
            tee_service,
        })
    }
}

impl<K: NetworkKeyProvider + Send + Sync + 'static> BuildableServer for EnclaveServer<K> {
    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn methods(self) -> Methods {
        self.into_rpc().into()
    }

    fn auth_secret(&self) -> Option<JwtSecret> {
        self.auth_secret
    }

    async fn start(self) -> Result<ServerHandle> {
        // No need for separate attestation init as TeeService handles this
        BuildableServer::start_rpc_server(self).await
    }
}

#[async_trait]
impl<K: NetworkKeyProvider + Send + Sync + 'static> EnclaveApiServer for EnclaveServer<K> {
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
