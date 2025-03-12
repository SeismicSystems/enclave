use jsonrpsee::{
    core::{ClientError, RpcResult},
    http_client::HttpClient,
    types::{ErrorCode, ErrorObject, ErrorObjectOwned},
};
use std::{
    net::{IpAddr, Ipv4Addr},
    ops::Deref,
};
use tokio::runtime::Runtime;

use crate::{
    ecdh_decrypt, ecdh_encrypt, get_unsecure_sample_schnorrkel_keypair,
    get_unsecure_sample_secp256k1_sk, rpc_invalid_ciphertext_error,
    tx_io::{IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse},
};

use super::rpc::SyncEnclaveApiClient;

pub const ENCLAVE_DEFAULT_ENDPOINT_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
pub const ENCLAVE_DEFAULT_ENDPOINT_PORT: u16 = 7878;

/// A client for the enclave API.
#[derive(Debug)]
pub struct EnclaveClient {
    /// The inner HTTP client.
    async_client: HttpClient,
    /// The runtime for the client.
    runtime: Runtime,
}

impl Default for EnclaveClient {
    fn default() -> Self {
        Self::new(format!(
            "http://{}:{}",
            ENCLAVE_DEFAULT_ENDPOINT_ADDR, ENCLAVE_DEFAULT_ENDPOINT_PORT
        ))
    }
}

impl Deref for EnclaveClient {
    type Target = HttpClient;

    fn deref(&self) -> &Self::Target {
        &self.async_client
    }
}

impl EnclaveClient {
    /// Create a new enclave client.
    pub fn new(url: impl AsRef<str>) -> Self {
        let inner = jsonrpsee::http_client::HttpClientBuilder::default()
            .build(url)
            .unwrap();
        Self {
            async_client: inner,
            runtime: Runtime::new().unwrap(),
        }
    }

    /// Create a new enclave client from an address and port.
    pub fn new_from_addr_port(addr: impl Into<String>, port: u16) -> Self {
        Self::new(format!("http://{}:{}", addr.into(), port))
    }
}

// impl SyncEnclaveApiClient for EnclaveClient {
//     fn health_check(&self) -> Result<String, ClientError> {
//         self.runtime.block_on(self.async_client.health_check())
//     }
// }

struct MockEnclaveClient;

impl SyncEnclaveApiClient for MockEnclaveClient {
    fn health_check(&self) -> RpcResult<String> {
        Ok("OK".to_string())
    }

    fn encrypt(&self, req: IoEncryptionRequest) -> RpcResult<IoEncryptionResponse> {
        // Use the sample secret key for encryption
        let encrypted_data = ecdh_encrypt(
            &req.key,
            &get_unsecure_sample_secp256k1_sk(),
            &req.data,
            req.nonce,
        )
        .unwrap();

        Ok(IoEncryptionResponse { encrypted_data })
    }

    fn decrypt(&self, req: IoDecryptionRequest) -> RpcResult<IoDecryptionResponse> {
        // Use the sample secret key for decryption
        let decrypted_data = ecdh_decrypt(
            &req.key,
            &get_unsecure_sample_secp256k1_sk(),
            &req.data,
            req.nonce,
        )
        .map_err(|e| rpc_invalid_ciphertext_error(e))?;

        Ok(IoDecryptionResponse { decrypted_data })
    }

    fn get_eph_rng_keypair(&self) -> RpcResult<schnorrkel::keys::Keypair> {
        // Return a sample Schnorrkel keypair for testing
        Ok(get_unsecure_sample_schnorrkel_keypair())
    }
}
