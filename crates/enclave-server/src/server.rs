use crate::coco_aa::{handlers::*, init_coco_aa};
use crate::coco_as::{handlers::*, init_coco_as};
use crate::genesis::handlers::*;
use crate::get_secp256k1_pk;
use crate::signing::handlers::*;
use crate::snapsync::handlers::*;
use crate::tx_io::handlers::*;

use seismic_enclave::coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse};
use seismic_enclave::coco_as::{AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse};
use seismic_enclave::genesis::GenesisDataResponse;
use seismic_enclave::rpc::EnclaveApiServer;
use seismic_enclave::signing::{
    Secp256k1SignRequest, Secp256k1SignResponse, Secp256k1VerifyRequest, Secp256k1VerifyResponse,
};
use seismic_enclave::snapsync::{SnapSyncRequest, SnapSyncResponse};
use seismic_enclave::tx_io::{
    IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse,
};

use anyhow::Result;
use jsonrpsee::core::{async_trait, RpcResult};
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use std::net::SocketAddr;
use tracing::{debug, info};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

pub struct EnclaveServer {}

impl EnclaveServer {
    pub async fn new() -> Result<Self> {
        init_coco_aa()?;
        init_coco_as(None).await?;
        Ok(Self {})
    }
}

// Implements the EnclaveApiServer trait to handle RPC requests for enclave operations
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
}

pub async fn start_rpc_server(addr: SocketAddr) -> Result<ServerHandle> {
    init_tracing();
    let server = EnclaveServer::new().await?;
    let module = server.into_rpc();
    let rpc_server = ServerBuilder::new().build(addr).await?;
    let server_handle = rpc_server.start(module);
    info!(target: "rpc::enclave", "Server started at {}", addr);
    Ok(server_handle)
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
