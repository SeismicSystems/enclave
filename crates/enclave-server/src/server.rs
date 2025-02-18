use crate::coco_aa::{handlers::*, init_coco_aa};
use crate::coco_as::{handlers::*, init_coco_as};
use crate::genesis::handlers::*;
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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tracing::{debug, info};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

pub const TEE_DEFAULT_ENDPOINT_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
pub const TEE_DEFAULT_ENDPOINT_PORT: u16 = 7878;

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
    /// Handler for: `health.check`
    async fn health_check(&self) -> RpcResult<String> {
        Ok("OK".into())
    }

    /// Handler for: `genesis.get_data`
    async fn genesis_get_data(&self) -> RpcResult<GenesisDataResponse> {
        debug!(target: "rpc::enclave", "Serving genesis.get_data");
        genesis_get_data_handler().await
    }

    /// Handler for: `snapsync.provide_backup`
    async fn provide_snapsync_backup(
        &self,
        request: SnapSyncRequest,
    ) -> RpcResult<SnapSyncResponse> {
        debug!(target: "rpc::enclave", "Serving snapsync.provide_backup");
        provide_snapsync_handler(request).await
    }

    /// Handler for: `tx_io.encrypt`
    async fn tx_io_encrypt(&self, req: IoEncryptionRequest) -> RpcResult<IoEncryptionResponse> {
        debug!(target: "rpc::enclave", "Serving tx_io.encrypt");
        tx_io_encrypt_handler(req).await
    }

    /// Handler for: `tx_io.decrypt`
    async fn tx_io_decrypt(&self, req: IoDecryptionRequest) -> RpcResult<IoDecryptionResponse> {
        debug!(target: "rpc::enclave", "Serving tx_io.decrypt");
        tx_io_decrypt_handler(req).await
    }

    /// Handler for: `attestation.aa.get_evidence`
    async fn attestation_get_evidence(
        &self,
        req: AttestationGetEvidenceRequest,
    ) -> RpcResult<AttestationGetEvidenceResponse> {
        debug!(target: "rpc::enclave", "Serving attestation.aa.get_evidence");
        attestation_get_evidence_handler(req).await
    }

    /// Handler for: `attestation.as.eval_evidence`
    async fn attestation_eval_evidence(
        &self,
        req: AttestationEvalEvidenceRequest,
    ) -> RpcResult<AttestationEvalEvidenceResponse> {
        debug!(target: "rpc::enclave", "Serving attestation.as.eval_evidence");
        attestation_eval_evidence_handler(req).await
    }

    /// Handler for: `signing.sign`
    async fn secp256k1_sign(&self, req: Secp256k1SignRequest) -> RpcResult<Secp256k1SignResponse> {
        debug!(target: "rpc::enclave", "Serving signing.sign");
        secp256k1_sign_handler(req).await
    }

    /// Handler for: `signing.verify`
    async fn secp256k1_verify(
        &self,
        req: Secp256k1VerifyRequest,
    ) -> RpcResult<Secp256k1VerifyResponse> {
        debug!(target: "rpc::enclave", "Serving signing.verify");
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

#[cfg(test)]
mod test {
    use crate::server::start_rpc_server;
    use crate::server::TEE_DEFAULT_ENDPOINT_ADDR;
    use crate::server::TEE_DEFAULT_ENDPOINT_PORT;
    use crate::utils::test_utils::is_sudo;
    use secp256k1::PublicKey;
    use seismic_enclave::request_types::tx_io::*;
    use seismic_enclave::rpc::EnclaveApiClient;
    use serial_test::serial;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::thread::sleep;
    use std::time::Duration;

    #[tokio::test]
    #[serial(attestation_agent, attestation_service)]
    async fn test_server_tx_io_req() {
        // handle set up permissions
        if !is_sudo() {
            eprintln!("test_server_tx_io_req: skipped (requires sudo privileges)");
            return;
        }

        // spawn a seperate thread for the server, otherwise the test will hang
        let addr = SocketAddr::from((TEE_DEFAULT_ENDPOINT_ADDR, TEE_DEFAULT_ENDPOINT_PORT));
        let _server_handle = start_rpc_server(addr).await.unwrap();
        sleep(Duration::from_secs(4));
        let client = jsonrpsee::http_client::HttpClientBuilder::default()
            .build(format!("http://{}:{}", addr.ip(), addr.port()))
            .unwrap();

        let _ = client.genesis_get_data().await.unwrap();

        // make the request struct
        let data_to_encrypt = vec![72, 101, 108, 108, 111];
        let mut nonce = vec![0u8; 4]; // 4 leading zeros
        nonce.extend_from_slice(&(12345678u64).to_be_bytes()); // Append the 8-byte u64
        let encryption_request = IoEncryptionRequest {
            key: PublicKey::from_str(
                "03e31e68908a6404a128904579c677534d19d0e5db80c7d9cf4de6b4b7fe0518bd",
            )
            .unwrap(),
            data: data_to_encrypt.clone(),
            nonce: nonce.clone().into(),
        };

        // make the http request
        let encryption_response = client.tx_io_encrypt(encryption_request).await.unwrap();

        // check the response
        assert!(!encryption_response.encrypted_data.is_empty());

        let decryption_request = IoDecryptionRequest {
            key: PublicKey::from_str(
                "03e31e68908a6404a128904579c677534d19d0e5db80c7d9cf4de6b4b7fe0518bd",
            )
            .unwrap(),
            data: encryption_response.encrypted_data,
            nonce: nonce.into(),
        };
        let decryption_response = client.tx_io_decrypt(decryption_request).await.unwrap();
        assert_eq!(decryption_response.decrypted_data, data_to_encrypt);
    }
}
