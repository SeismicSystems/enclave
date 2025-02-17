use crate::get_sample_schnorrkel_keypair;

use super::*;
use jsonrpsee::core::RpcResult;
use reqwest::Client;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// Unspecified (0.0.0.0) exposes to public internet
// Localhost (127.0.0.1) will only allow other processes on machine to ping
pub const TEE_DEFAULT_ENDPOINT_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
pub const TEE_DEFAULT_ENDPOINT_PORT: u16 = 7878;

/// An implementation of the TEE client API that
/// makes HTTP requests to the TEE server
#[derive(Debug, Clone)]
pub struct TeeHttpClient {
    /// url of the TEE server
    pub base_url: String,
    /// HTTP client for making requests
    pub client: Client,
}

impl Default for TeeHttpClient {
    fn default() -> Self {
        Self {
            base_url: format!(
                "http://{}:{}",
                TEE_DEFAULT_ENDPOINT_ADDR, TEE_DEFAULT_ENDPOINT_PORT
            ),
            client: Client::new(),
        }
    }
}

impl TeeHttpClient {
    /// Creates a new instance of the TEE client
    pub fn new(base_url: String) -> Self {
        println!("Base URL: {}", base_url);
        Self {
            base_url,
            client: Client::new(),
        }
    }

    /// Creates a new instance of the TEE client
    pub fn new_from_addr_port(addr: IpAddr, port: u16) -> Self {
        Self {
            base_url: format!("http://{}:{}", addr, port),
            client: Client::new(),
        }
    }

    pub fn new_from_addr(addr: &SocketAddr) -> Self {
        let base_url = format!("http://{}", addr);
        println!("Base URL: {}", base_url);
        Self {
            base_url,
            client: Client::new(),
        }
    }
}

#[derive(Deserialize)]
pub struct TeeErrorResponse {
    error: String,
}

impl TeeAPI for TeeHttpClient {
    async fn genesis_data(
        &self,
        payload: GenesisData,
    ) -> Result<GenesisDataResponse, anyhow::Error> {
        let payload_json = serde_json::to_string(&payload)?;
        let response = self
            .client
            .post(format!("{}/genesis/data", self.base_url))
            .header("Content-Type", "application/json")
            .body(payload_json)
            .send()
            .await?;

        let body = response.bytes().await?.to_vec();
        let genesis_response: GenesisDataResponse = serde_json::from_slice(&body)?;
        Ok(genesis_response)
    }

    async fn attestation_get_evidence(
        &self,
        payload: AttestationGetEvidenceRequest,
    ) -> Result<AttestationGetEvidenceResponse, anyhow::Error> {
        let payload_json = serde_json::to_string(&payload)?;
        let response = self
            .client
            .post(format!("{}/attestation/evidence/get", self.base_url))
            .header("Content-Type", "application/json")
            .body(payload_json)
            .send()
            .await?;

        let body = response.bytes().await?.to_vec();
        let attestation_response: AttestationGetEvidenceResponse = serde_json::from_slice(&body)?;
        Ok(attestation_response)
    }

    async fn attestation_eval_evidence(
        &self,
        payload: AttestationEvalEvidenceRequest,
    ) -> Result<AttestationEvalEvidenceResponse, anyhow::Error> {
        let payload_json = serde_json::to_string(&payload)?;
        let response = self
            .client
            .post(format!("{}/attestation/evidence/evaluate", self.base_url))
            .header("Content-Type", "application/json")
            .body(payload_json)
            .send()
            .await?;

        let body = response.bytes().await?.to_vec();
        let evaluation_response: AttestationEvalEvidenceResponse = serde_json::from_slice(&body)?;
        Ok(evaluation_response)
    }

    async fn signing_sign(
        &self,
        payload: Secp256k1SignRequest,
    ) -> Result<Secp256k1SignResponse, anyhow::Error> {
        let payload_json = serde_json::to_string(&payload)?;
        let response = self
            .client
            .post(format!("{}/signing/sign", self.base_url))
            .header("Content-Type", "application/json")
            .body(payload_json)
            .send()
            .await?;

        let body = response.bytes().await?.to_vec();
        let sign_response: Secp256k1SignResponse = serde_json::from_slice(&body)?;
        Ok(sign_response)
    }

    async fn signing_verify(
        &self,
        payload: Secp256k1VerifyRequest,
    ) -> Result<Secp256k1VerifyResponse, anyhow::Error> {
        let payload_json = serde_json::to_string(&payload)?;
        let response = self
            .client
            .post(format!("{}/signing/verify", self.base_url))
            .header("Content-Type", "application/json")
            .body(payload_json)
            .send()
            .await?;

        let body = response.bytes().await?.to_vec();
        let verify_response: Secp256k1VerifyResponse = serde_json::from_slice(&body)?;
        Ok(verify_response)
    }

    async fn tx_io_encrypt(
        &self,
        payload: IoEncryptionRequest,
    ) -> Result<IoEncryptionResponse, anyhow::Error> {
        let payload_json = serde_json::to_string(&payload)?;

        // Using reqwest's Client to send a POST request
        let response = self
            .client
            .post(format!("{}/tx_io/encrypt", self.base_url))
            .header("Content-Type", "application/json")
            .body(payload_json)
            .send()
            .await?;

        if !response.status().is_success() {
            let error: TeeErrorResponse = serde_json::from_str(&response.text().await?)?;
            return Err(anyhow::anyhow!(error.error));
        }

        // Extract the response body as bytes
        let body: Vec<u8> = response.bytes().await?.to_vec();

        // Parse the response body into the IoEncryptionResponse struct
        let enc_response: IoEncryptionResponse = serde_json::from_slice(&body)?;

        Ok(enc_response)
    }

    async fn tx_io_decrypt(
        &self,
        payload: IoDecryptionRequest,
    ) -> Result<IoDecryptionResponse, anyhow::Error> {
        let payload_json = serde_json::to_string(&payload)?;

        // Using reqwest's Client to send a POST request
        let response = self
            .client
            .post(format!("{}/tx_io/decrypt", self.base_url))
            .header("Content-Type", "application/json")
            .body(payload_json)
            .send()
            .await?;

        if !response.status().is_success() {
            let error: TeeErrorResponse = serde_json::from_str(&response.text().await?)?;
            return Err(anyhow::anyhow!(error.error));
        }
        // Extract the response body as bytes
        let body: Vec<u8> = response.bytes().await?.to_vec();

        // Parse the response body into the IoDecryptionResponse struct
        let dec_response: IoDecryptionResponse = serde_json::from_slice(&body)?;

        Ok(dec_response)
    }

    async fn get_eph_rng_keypair(&self) -> RpcResult<schnorrkel::keys::Keypair> {
        Ok(get_sample_schnorrkel_keypair())
    }
}
