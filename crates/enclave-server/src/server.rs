use crate::coco_aa::{handlers::*, init_coco_aa};
use crate::coco_as::{handlers::*, init_coco_as};
use crate::genesis::handlers::*;
use crate::key_manager::key_manager::{KeyManager, OperatorShare};
use crate::signing::handlers::*;
use crate::snapshot::handlers::*;
use crate::snapsync::handlers::*;
use crate::tx_io::handlers::*;
use crate::{get_schnorrkel_keypair, get_secp256k1_pk};

use seismic_enclave::coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse};
use seismic_enclave::coco_as::{AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse};
use seismic_enclave::genesis::GenesisDataResponse;
use seismic_enclave::rpc::{BuildableServer, EnclaveApiServer};
use seismic_enclave::signing::{
    Secp256k1SignRequest, Secp256k1SignResponse, Secp256k1VerifyRequest, Secp256k1VerifyResponse,
};
use seismic_enclave::snapshot::{
    PrepareEncryptedSnapshotRequest, PrepareEncryptedSnapshotResponse,
    RestoreFromEncryptedSnapshotRequest, RestoreFromEncryptedSnapshotResponse,
};
use seismic_enclave::snapsync::{SnapSyncRequest, SnapSyncResponse};
use seismic_enclave::tx_io::{
    IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse,
};
use seismic_enclave::{ENCLAVE_DEFAULT_ENDPOINT_ADDR, ENCLAVE_DEFAULT_ENDPOINT_PORT};

use anyhow::{anyhow, Result};
use jsonrpsee::core::{async_trait, RpcResult};
use jsonrpsee::server::ServerHandle;
use jsonrpsee::Methods;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tracing::{debug, info};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

/// The main server struct, with everything needed to run.
pub struct EnclaveServer {
    addr: SocketAddr,
    key_manager: KeyManager, 
}

/// A builder that lets us configure the server address and optionally add operator shares.
pub struct EnclaveServerBuilder {
    addr: Option<SocketAddr>,
    operator_shares: Vec<OperatorShare>,
}

impl EnclaveServer {
    pub async fn init_attestation() -> Result<()> {
        init_coco_aa()?;
        init_coco_as(None).await?;
        Ok(())
    }

    /// Create a new builder with default address and no shares.
    pub fn builder() -> EnclaveServerBuilder {
        EnclaveServerBuilder::default()
    }

    /// Provide direct constructor if you *really* want to skip the builder. 
    /// By default, this will do a "test" KeyManager.
    pub fn new(addr: impl Into<SocketAddr>) -> Self {
        Self {
            addr: addr.into(),
            key_manager: KeyManager::new_with_test_shares(),
        }
    }

    /// Example constructor from IP/port strings.
    pub fn new_from_addr_port(addr: String, port: u16) -> Self {
        Self::new((IpAddr::from_str(&addr).unwrap(), port))
    }

    /// If you want to keep chainable `with_addr` / `with_port` on the server itself:
    pub fn with_addr(mut self, addr: &str) -> Self {
        let ip_addr = IpAddr::from_str(addr).unwrap();
        self.addr = SocketAddr::new(ip_addr, self.addr.port());
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.addr = SocketAddr::new(self.addr.ip(), port);
        self
    }
}

/// By default, we create a server on 0.0.0.0:4242 with a test KeyManager.
impl Default for EnclaveServer {
    fn default() -> Self {
        Self::new((ENCLAVE_DEFAULT_ENDPOINT_ADDR, ENCLAVE_DEFAULT_ENDPOINT_PORT))
    }
}

/// Implementation of our new builder.
impl Default for EnclaveServerBuilder {
    fn default() -> Self {
        Self {
            addr: Some(SocketAddr::new(
                ENCLAVE_DEFAULT_ENDPOINT_ADDR,
                ENCLAVE_DEFAULT_ENDPOINT_PORT,
            )),
            operator_shares: Vec::new(),
        }
    }
}

impl EnclaveServerBuilder {
    pub fn with_addr(mut self, addr: &str) -> Self {
        let ip_addr = IpAddr::from_str(addr).unwrap();
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
            self.addr = Some(SocketAddr::new(
                ENCLAVE_DEFAULT_ENDPOINT_ADDR,
                port,
            ));
        }
        self
    }

    /// Add an operator share; if present, we'll treat as production mode.
    pub fn with_operator_share(mut self, share: OperatorShare) -> Self {
        self.operator_shares.push(share);
        self
    }

    /// Build the final `EnclaveServer` object.
    pub fn build(self) -> Result<EnclaveServer> {
        let final_addr = self.addr.ok_or_else(|| {
            anyhow!("No address found in builder (should not happen if default is set)")
        })?;

        let key_manager = if !self.operator_shares.is_empty() {
            KeyManager::new_with_shares(&self.operator_shares)?
        } else {
            KeyManager::new_with_test_shares()
        };

        Ok(EnclaveServer {
            addr: final_addr,
            key_manager,
        })
    }
}

impl BuildableServer for EnclaveServer {
    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn methods(self) -> Methods {
        self.into_rpc().into()
    }

    async fn start(self) -> Result<ServerHandle> {
        Self::init_attestation().await?;
        BuildableServer::start_rpc_server(self).await
    }
}

#[async_trait]
impl EnclaveApiServer for EnclaveServer {
    /// Handler for: `getPublicKey`
    async fn get_public_key(&self) -> RpcResult<secp256k1::PublicKey> {
        Ok(get_secp256k1_pk())
    }

    /// Handler for: `healthCheck`
    async fn health_check(&self) -> RpcResult<String> {
        Ok("OK".into())
    }

    /// Handler for: `getGenesisData`
    async fn get_genesis_data(&self) -> RpcResult<GenesisDataResponse> {
        debug!(target: "rpc::enclave", "Serving getGenesisData");
        genesis_get_data_handler().await
    }

    /// Handler for: `getSnapsyncBackup`
    async fn get_snapsync_backup(&self, request: SnapSyncRequest) -> RpcResult<SnapSyncResponse> {
        debug!(target: "rpc::enclave", "Serving getSnapsyncBackup");
        provide_snapsync_handler(request).await
    }

    /// Handler for: `encrypt`
    async fn encrypt(&self, req: IoEncryptionRequest) -> RpcResult<IoEncryptionResponse> {
        debug!(target: "rpc::enclave", "Serving encrypt");
        tx_io_encrypt_handler(req).await
    }

    /// Handler for: `decrypt`
    async fn decrypt(&self, req: IoDecryptionRequest) -> RpcResult<IoDecryptionResponse> {
        debug!(target: "rpc::enclave", "Serving decrypt");
        tx_io_decrypt_handler(req).await
    }

    /// Handler for: `getAttestationEvidence`
    async fn get_attestation_evidence(
        &self,
        req: AttestationGetEvidenceRequest,
    ) -> RpcResult<AttestationGetEvidenceResponse> {
        debug!(target: "rpc::enclave", "Serving getAttestationEvidence");
        attestation_get_evidence_handler(req).await
    }

    /// Handler for: `evalAttestationEvidence`
    async fn eval_attestation_evidence(
        &self,
        req: AttestationEvalEvidenceRequest,
    ) -> RpcResult<AttestationEvalEvidenceResponse> {
        debug!(target: "rpc::enclave", "Serving evalAttestationEvidence");
        attestation_eval_evidence_handler(req).await
    }

    /// Handler for: `sign`
    async fn sign(&self, req: Secp256k1SignRequest) -> RpcResult<Secp256k1SignResponse> {
        debug!(target: "rpc::enclave", "Serving sign");
        secp256k1_sign_handler(req).await
    }

    /// Handler for: `verify`
    async fn verify(&self, req: Secp256k1VerifyRequest) -> RpcResult<Secp256k1VerifyResponse> {
        debug!(target: "rpc::enclave", "Serving verify");
        secp256k1_verify_handler(req).await
    }

    /// Handler for: 'eph_rng.get_keypair'
    async fn get_eph_rng_keypair(&self) -> RpcResult<schnorrkel::keys::Keypair> {
        debug!(target: "rpc::enclave", "Serving eph_rng.get_keypair");
        Ok(get_schnorrkel_keypair())
    }

    /// Handler for: 'snapshot.prepare_encrypted_snapshot'
    async fn prepare_encrypted_snapshot(
        &self,
        req: PrepareEncryptedSnapshotRequest,
    ) -> RpcResult<PrepareEncryptedSnapshotResponse> {
        debug!(target: "rpc::enclave", "Serving snapshot.prepare_encrypted_snapshot");
        prepare_encrypted_snapshot_handler(req).await
    }

    /// Handler for: 'snapshot.restore_from_encrypted_snapshot'
    async fn restore_from_encrypted_snapshot(
        &self,
        req: RestoreFromEncryptedSnapshotRequest,
    ) -> RpcResult<RestoreFromEncryptedSnapshotResponse> {
        debug!(target: "rpc::enclave", "Serving snapshot.restore_from_encrypted_snapshot");
        restore_from_encrypted_snapshot_handler(req).await
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
