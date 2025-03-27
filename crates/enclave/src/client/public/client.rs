use jsonrpsee::{core::ClientError, http_client::HttpClient};
use std::{ops::Deref, time::Duration};
use tokio::runtime::{Handle, Runtime};

use super::{EnclavePublicAPIClient, SyncEnclavePublicAPIClient};
use crate::client::builder::BuildableClient;
use crate::client::{
    ENCLAVE_CLIENT_RUNTIME, ENCLAVE_DEFAULT_ENDPOINT_ADDR, ENCLAVE_DEFAULT_INTERNAL_PORT,
};

/// A client for the enclave API.
#[derive(Debug, Clone)]
pub struct EnclavePublicClient {
    /// The inner HTTP client.
    async_client: HttpClient,
    /// The runtime for the client.
    handle: Handle,
}

impl Default for EnclavePublicClient {
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
impl Deref for EnclavePublicClient {
    type Target = HttpClient;

    fn deref(&self) -> &Self::Target {
        &self.async_client
    }
}
impl BuildableClient for EnclavePublicClient {
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

    fn get_handle(&self) -> &Handle {
        &self.handle
    }
}

macro_rules! impl_sync_client_trait {
    ($(fn $method_name:ident(&self $(, $param:ident: $param_ty:ty)*) -> $return_ty:ty),* $(,)?) => {
        impl SyncEnclavePublicAPIClient for EnclavePublicClient {
            $(
                fn $method_name(&self, $($param: $param_ty),*) -> $return_ty {
                    self.block_on_with_runtime(self.async_client.$method_name($($param),*))
                }
            )+
        }
    };
}

impl_sync_client_trait!(
    fn health_check(&self) -> Result<String, ClientError>,
    fn get_public_key(&self) -> Result<secp256k1::PublicKey, ClientError>,
);
