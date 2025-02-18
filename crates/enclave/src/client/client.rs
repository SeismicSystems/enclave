use jsonrpsee::http_client::HttpClient;
use std::{
    net::{IpAddr, Ipv4Addr},
    ops::Deref,
};

pub const TEE_DEFAULT_ENDPOINT_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
pub const TEE_DEFAULT_ENDPOINT_PORT: u16 = 7878;

/// A client for the enclave API.
#[derive(Debug, Clone)]
pub struct EnclaveClient {
    /// The inner HTTP client.
    inner: HttpClient,
}

impl Default for EnclaveClient {
    fn default() -> Self {
        Self::new(format!(
            "http://{}:{}",
            TEE_DEFAULT_ENDPOINT_ADDR, TEE_DEFAULT_ENDPOINT_PORT
        ))
    }
}

impl Deref for EnclaveClient {
    type Target = HttpClient;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl EnclaveClient {
    /// Create a new enclave client.
    pub fn new(url: impl AsRef<str>) -> Self {
        let inner = jsonrpsee::http_client::HttpClientBuilder::default()
            .build(url)
            .unwrap();
        Self { inner }
    }
}
