//! A http client for interacting with a enclave server.
//! Comnstructed from a [`EnclaveClientBuilder`].

use anyhow::Result;
use jsonrpsee::http_client::transport::HttpBackend;
use jsonrpsee::{core::ClientError, http_client::HttpClient};
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr},
    ops::Deref,
    sync::OnceLock,
    time::Duration,
};
use tokio::runtime::{Handle, Runtime};

use super::rpc::{EnclaveApiClient, SyncEnclaveApiClient, SyncEnclaveApiClientBuilder};
use crate::request_types::*;

pub const ENCLAVE_DEFAULT_ENDPOINT_IP: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
pub const ENCLAVE_DEFAULT_ENDPOINT_PORT: u16 = 7878;
pub const ENCLAVE_DEFAULT_TIMEOUT_SECONDS: u64 = 5;
static ENCLAVE_CLIENT_RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// The inner async HTTP client.
/// Useful to define here in case the HttpClient<T> generic changes
type EnclaveHttpClient = HttpClient<HttpBackend>;

/// Builder for [`EnclaveClient`].
#[derive(Debug, Clone)]
pub struct EnclaveClientBuilder {
    ip: Option<String>,
    port: Option<u16>,
    timeout: Option<Duration>,
    url: Option<String>,
}

impl EnclaveClientBuilder {
    pub fn new() -> Self {
        Self {
            ip: None,
            port: None,
            timeout: None,
            url: None,
        }
    }

    pub fn ip(mut self, ip: impl Into<String>) -> Self {
        self.ip = Some(ip.into());
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    pub fn build(self) -> Result<EnclaveClient> {
        let url = self.url.unwrap_or_else(|| {
            format!(
                "http://{}:{}",
                self.ip
                    .unwrap_or_else(|| ENCLAVE_DEFAULT_ENDPOINT_IP.to_string()),
                self.port.unwrap_or(ENCLAVE_DEFAULT_ENDPOINT_PORT)
            )
        });

        let async_client: EnclaveHttpClient = jsonrpsee::http_client::HttpClientBuilder::default()
            .request_timeout(
                self.timeout
                    .unwrap_or(Duration::from_secs(ENCLAVE_DEFAULT_TIMEOUT_SECONDS)),
            )
            .build(url)
            .unwrap();

        Ok(EnclaveClient::new_from_client(async_client))
    }
}

impl Default for EnclaveClientBuilder {
    fn default() -> Self {
        let mut builder = EnclaveClientBuilder::new();

        let url = format!(
            "http://{}:{}",
            ENCLAVE_DEFAULT_ENDPOINT_IP, ENCLAVE_DEFAULT_ENDPOINT_PORT
        );
        builder = builder.url(url);
        builder = builder.timeout(Duration::from_secs(5));
        builder
    }
}

impl SyncEnclaveApiClientBuilder for EnclaveClientBuilder {
    type Client = EnclaveClient;
    fn build(self) -> EnclaveClient {
        EnclaveClientBuilder::build(self).unwrap()
    }
}

/// A client for the enclave API.
#[derive(Debug, Clone)]
pub struct EnclaveClient {
    /// The inner HTTP client.
    async_client: EnclaveHttpClient,
    /// The runtime for the client.
    handle: Handle,
}
impl Deref for EnclaveClient {
    type Target = EnclaveHttpClient;

    fn deref(&self) -> &Self::Target {
        &self.async_client
    }
}
impl Default for EnclaveClient {
    fn default() -> Self {
        EnclaveClientBuilder::default().build().unwrap()
    }
}

impl EnclaveClient {
    pub fn builder() -> EnclaveClientBuilder {
        EnclaveClientBuilder::new()
    }

    /// Create a new [`EnclaveClient`] from an [`EnclaveHttpClient`].
    pub fn new_from_client(async_client: EnclaveHttpClient) -> Self {
        let handle = Handle::try_current().unwrap_or_else(|_| {
            let runtime = ENCLAVE_CLIENT_RUNTIME.get_or_init(|| Runtime::new().unwrap());
            runtime.handle().clone()
        });
        Self {
            async_client,
            handle,
        }
    }

    /// Block on a future with the runtime.
    pub fn block_on_with_runtime<F, T>(&self, future: F) -> T
    where
        F: Future<Output = T>,
    {
        tokio::task::block_in_place(|| self.handle.block_on(future))
    }

    /// A client enclave bade to work with the default mock server
    /// Useful for testing
    pub fn mock(ip: String, port: u16) -> Result<Self> {
        let client = EnclaveClientBuilder::new()
            .ip(ip)
            .port(port)
            .timeout(Duration::from_secs(ENCLAVE_DEFAULT_TIMEOUT_SECONDS))
            .build()?;
        Ok(client)
    }
}

// impl the SyncEnclaveApiClient trait for EnclaveClient based on the [`EnclaveApi`] trait
macro_rules! impl_sync_client_trait {
    ($(fn $method_name:ident(&self $(, $param:ident: $param_ty:ty)*) -> $return_ty:ty),* $(,)?) => {
        impl SyncEnclaveApiClient for EnclaveClient {
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
    fn get_purpose_keys(&self, _req: GetPurposeKeysRequest) -> Result<GetPurposeKeysResponse, ClientError>,
    fn get_attestation_evidence(&self, _req: AttestationGetEvidenceRequest) -> Result<AttestationGetEvidenceResponse, ClientError>,
    fn eval_attestation_evidence(&self, _req: AttestationEvalEvidenceRequest) -> Result<AttestationEvalEvidenceResponse, ClientError>,
    fn boot_retrieve_root_key(&self, _req: RetrieveRootKeyRequest) -> Result<RetrieveRootKeyResponse,  ClientError>,
    fn boot_share_root_key(&self, _req: ShareRootKeyRequest) -> Result<ShareRootKeyResponse,  ClientError>,
    fn boot_genesis(&self) -> Result<(),  ClientError>,
    fn complete_boot(&self) -> Result<(),  ClientError>,
);

#[cfg(test)]
pub mod tests {
    use crate::{rpc::BuildableServer, MockEnclaveServer};

    use super::*;
    use std::{
        net::{SocketAddr, TcpListener},
        time::Duration,
    };
    use tokio::time::sleep;

    #[test]
    fn test_client_sync_context() {
        // testing if sync client can be created in a sync runtime
        let port = get_random_port();
        let addr = SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_IP, port));
        let _ = EnclaveClient::mock(addr.ip().to_string(), addr.port());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sync_client() -> Result<()> {
        // spawn a seperate thread for the server, otherwise the test will hang
        let port = get_random_port();
        let addr = SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_IP, port));
        let _server_handle = MockEnclaveServer::new(addr).start().await?;
        let _ = sleep(Duration::from_secs(2)).await;

        let client = EnclaveClient::mock(addr.ip().to_string(), addr.port())?;
        sync_test_health_check(&client);
        Ok(())
    }

    pub fn get_random_port() -> u16 {
        TcpListener::bind("127.0.0.1:0") // 0 means OS assigns a free port
            .expect("Failed to bind to a port")
            .local_addr()
            .unwrap()
            .port()
    }

    pub fn sync_test_health_check<C: SyncEnclaveApiClient>(client: &C) {
        let resposne = client.health_check().unwrap();
        assert_eq!(resposne, "OK");
    }

    pub fn sync_test_get_purpose_keys<C: SyncEnclaveApiClient>(client: &C) {
        let response = client
            .get_purpose_keys(GetPurposeKeysRequest { epoch: 0 })
            .unwrap();
        assert!(response.snapshot_key_bytes.len() > 0);
    }
}
