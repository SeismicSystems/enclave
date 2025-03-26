use jsonrpsee::{core::ClientError, http_client::HttpClient};
use std::{future::Future, ops::Deref, time::Duration};
use tokio::runtime::{Handle, Runtime};

use super::{EnclaveInternalAPIClient, SyncEnclaveInternalAPIClient};
use crate::client::client::BuildableClient;
use crate::client::client::EnclaveClientBuilder;
use crate::client::{
    ENCLAVE_CLIENT_RUNTIME, ENCLAVE_DEFAULT_ENDPOINT_ADDR, ENCLAVE_DEFAULT_INTERNAL_PORT,
};
use crate::{
    coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse},
    coco_as::{AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse},
    signing::{
        Secp256k1SignRequest, Secp256k1SignResponse, Secp256k1VerifyRequest,
        Secp256k1VerifyResponse,
    },
    tx_io::{IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse},
};

/// A client for the enclave API.
#[derive(Debug, Clone)]
pub struct EnclaveInternalClient {
    /// The inner HTTP client.
    async_client: HttpClient,
    /// The runtime for the client.
    handle: Handle,
}

impl Default for EnclaveInternalClient {
    fn default() -> Self {
        let url = format!(
            "http://{}:{}",
            ENCLAVE_DEFAULT_ENDPOINT_ADDR, ENCLAVE_DEFAULT_INTERNAL_PORT
        );
        let async_client = jsonrpsee::http_client::HttpClientBuilder::default()
            .request_timeout(Duration::from_secs(5))
            .build(url)
            .unwrap();
        Self::new_from_client(async_client)
    }
}

impl Deref for EnclaveInternalClient {
    type Target = HttpClient;

    fn deref(&self) -> &Self::Target {
        &self.async_client
    }
}
impl BuildableClient for EnclaveInternalClient {
    fn new_from_client(async_client: HttpClient) -> Self {
        let handle = Handle::try_current().unwrap_or_else(|_| {
            let runtime = ENCLAVE_CLIENT_RUNTIME.get_or_init(|| Runtime::new().unwrap());
            runtime.handle().clone()
        });
        Self {
            async_client,
            handle,
        }
    }
    fn default_port() -> u16 {
        ENCLAVE_DEFAULT_INTERNAL_PORT
    }
}
impl EnclaveInternalClient {
    pub fn builder() -> EnclaveClientBuilder<Self> {
        EnclaveClientBuilder::new()
    }

    /// Create a new enclave client.
    pub fn new(url: impl AsRef<str>) -> Self {
        EnclaveClientBuilder::new().url(url.as_ref()).build()
    }

    /// Create a new enclave client from an address and port.
    pub fn new_from_addr_port(addr: impl Into<String>, port: u16) -> Self {
        EnclaveClientBuilder::new().addr(addr).port(port).build()
    }

    /// Block on a future with the runtime.
    pub fn block_on_with_runtime<F, T>(&self, future: F) -> T
    where
        F: Future<Output = T>,
    {
        tokio::task::block_in_place(|| self.handle.block_on(future))
    }
}

macro_rules! impl_sync_client_trait {
    ($(fn $method_name:ident(&self $(, $param:ident: $param_ty:ty)*) -> $return_ty:ty),* $(,)?) => {
        impl SyncEnclaveInternalAPIClient for EnclaveInternalClient {
            $(
                fn $method_name(&self, $($param: $param_ty),*) -> $return_ty {
                    self.block_on_with_runtime(self.async_client.$method_name($($param),*))
                }
            )+
        }
    };
}

impl_sync_client_trait!(
    fn encrypt(&self, req: IoEncryptionRequest) -> Result<IoEncryptionResponse, ClientError>,
    fn decrypt(&self, req: IoDecryptionRequest) -> Result<IoDecryptionResponse, ClientError>,
    fn sign(&self, _req: Secp256k1SignRequest) -> Result<Secp256k1SignResponse, ClientError>,
    fn verify(&self, _req: Secp256k1VerifyRequest) -> Result<Secp256k1VerifyResponse, ClientError>,
    fn get_attestation_evidence(&self, _req: AttestationGetEvidenceRequest) -> Result<AttestationGetEvidenceResponse, ClientError>,
    fn eval_attestation_evidence(&self, _req: AttestationEvalEvidenceRequest) -> Result<AttestationEvalEvidenceResponse, ClientError>,
    fn get_eph_rng_keypair(&self) -> Result<schnorrkel::keys::Keypair, ClientError>,
);
