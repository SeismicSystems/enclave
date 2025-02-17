use crate::coco_aa::{handlers::*, init_coco_aa};
use crate::coco_as::{handlers::*, init_coco_as};
use crate::genesis::handlers::*;
use crate::signing::handlers::*;
use crate::snapsync::handlers::*;
use crate::tx_io::handlers::*;

use anyhow::Result;
use jsonrpsee::core::{async_trait, RpcResult};
use jsonrpsee::server::ServerBuilder;
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
use std::net::SocketAddr;
use 

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
        trace!(target: "rpc::enclave", "Serving genesis.get_data");
        genesis_get_data_handler().await
    }

    /// Handler for: `snapsync.provide_backup`
    async fn provide_snapsync_backup(
        &self,
        request: SnapSyncRequest,
    ) -> RpcResult<SnapSyncResponse> {
        trace!(target: "rpc::enclave", "Serving snapsync.provide_backup");
        provide_snapsync_handler(request).await
    }

    /// Handler for: `tx_io.encrypt`
    async fn tx_io_encrypt(&self, req: IoEncryptionRequest) -> RpcResult<IoEncryptionResponse> {
        trace!(target: "rpc::enclave", "Serving tx_io.encrypt");
        tx_io_encrypt_handler(req).await
    }

    /// Handler for: `tx_io.decrypt`
    async fn tx_io_decrypt(&self, req: IoDecryptionRequest) -> RpcResult<IoDecryptionResponse> {
        trace!(target: "rpc::enclave", "Serving tx_io.decrypt");
        tx_io_decrypt_handler(req).await
    }

    /// Handler for: `attestation.aa.get_evidence`
    async fn attestation_get_evidence(
        &self,
        req: AttestationGetEvidenceRequest,
    ) -> RpcResult<AttestationGetEvidenceResponse> {
        trace!(target: "rpc::enclave", "Serving attestation.aa.get_evidence");
        attestation_get_evidence_handler(req).await
    }

    /// Handler for: `attestation.as.eval_evidence`
    async fn attestation_eval_evidence(
        &self,
        req: AttestationEvalEvidenceRequest,
    ) -> RpcResult<AttestationEvalEvidenceResponse> {
        trace!(target: "rpc::enclave", "Serving attestation.as.eval_evidence");
        attestation_eval_evidence_handler(req).await
    }

    /// Handler for: `signing.sign`
    async fn secp256k1_sign(&self, req: Secp256k1SignRequest) -> RpcResult<Secp256k1SignResponse> {
        trace!(target: "rpc::enclave", "Serving signing.sign");
        secp256k1_sign_handler(req).await
    }

    /// Handler for: `signing.verify`
    async fn secp256k1_verify(
        &self,
        req: Secp256k1VerifyRequest,
    ) -> RpcResult<Secp256k1VerifyResponse> {
        trace!(target: "rpc::enclave", "Serving signing.verify");
        secp256k1_verify_handler(req).await
    }
}

pub async fn start_rpc_server(addr: SocketAddr) -> Result<()> {
    let server = EnclaveServer::new().await?;
    let module = server.into_rpc();
    let rpc_server = ServerBuilder::new().build(addr).await?;
    let server_handle = rpc_server.start(module);
    server_handle.stopped().await;
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::server::start_rpc_server;
    use crate::utils::test_utils::is_sudo;
    use seismic_enclave::client::http_client::TeeHttpClient;
    use seismic_enclave::client::http_client::{
        TEE_DEFAULT_ENDPOINT_ADDR, TEE_DEFAULT_ENDPOINT_PORT,
    };
    use seismic_enclave::request_types::tx_io::*;
    use seismic_enclave::TeeAPI;

    use secp256k1::PublicKey;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use tokio::time::Duration;
    use tokio::time::Instant;

    #[ignore]
    #[tokio::test]
    async fn test_server_tx_io_req() {
        // handle set up permissions
        if !is_sudo() {
            eprintln!("test_server_tx_io_req: skipped (requires sudo privileges)");
            return;
        }

        // spawn a seperate thread for the server, otherwise the test will hang
        let addr = SocketAddr::from((TEE_DEFAULT_ENDPOINT_ADDR, TEE_DEFAULT_ENDPOINT_PORT));
        let _server_handle = tokio::spawn(start_rpc_server(addr));
        let wait_duration = Duration::from_secs(2);
        wait_for_server(&format!("{}/health", addr), wait_duration)
            .await
            .unwrap();

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
        let http_cleint = TeeHttpClient::default();
        let encryption_response = http_cleint.tx_io_encrypt(encryption_request).await.unwrap();

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
        let decryption_response = http_cleint.tx_io_decrypt(decryption_request).await.unwrap();
        assert_eq!(decryption_response.decrypted_data, data_to_encrypt);
    }

    async fn wait_for_server(
        addr: &str,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if reqwest::get(addr).await.is_ok() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err("Server did not start in time".into())
    }
}
