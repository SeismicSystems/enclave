use jsonrpsee::{core::ClientError, http_client::HttpClient};
use std::{
    future::Future, net::{IpAddr, Ipv4Addr}, ops::Deref, sync::OnceLock, time::Duration
};
use tokio::runtime::{Handle, Runtime};

use crate::{
    coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse},
    coco_as::{AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse},
    genesis::GenesisDataResponse,
    signing::{
        Secp256k1SignRequest, Secp256k1SignResponse,
    },
    tx_io::{IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse},
};
use super::rpc::{EnclaveApiClient, SyncEnclaveApiClient};

use crate::auth::{JwtSecret, AuthClientLayer, AuthClientService};
use jsonrpsee::http_client::transport::HttpBackend;

pub const ENCLAVE_DEFAULT_ENDPOINT_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
pub const ENCLAVE_DEFAULT_ENDPOINT_PORT: u16 = 7878;
pub const ENCLAVE_DEFAULT_TIMEOUT_SECONDS: u64 = 5;
static ENCLAVE_CLIENT_RUNTIME: OnceLock<Runtime> = OnceLock::new();

pub struct EnclaveClientBuilder {
    addr: Option<String>,
    port: Option<u16>,
    timeout: Option<Duration>,
    url: Option<String>,
    auth_secret: Option<JwtSecret>,
}

impl EnclaveClientBuilder {
    pub fn new() -> Self {
        Self {
            addr: None,
            port: None,
            timeout: None,
            url: None,
            auth_secret: None,
        }
    }

    pub fn addr(mut self, addr: impl Into<String>) -> Self {
        self.addr = Some(addr.into());
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

    pub fn auth_secret(mut self, auth_secret: JwtSecret) -> Self {
        self.auth_secret = Some(auth_secret);
        self
    }

    pub fn build(self) -> EnclaveClient {
        let auth_secret = self.auth_secret.unwrap_or_else(|| {
            // TODO: better error handling
            panic!("No auth secret supplied to builder")
        });

        let url = self.url.unwrap_or_else(|| {
            format!(
                "http://{}:{}",
                self.addr
                    .unwrap_or_else(|| ENCLAVE_DEFAULT_ENDPOINT_ADDR.to_string()),
                self.port.unwrap_or(ENCLAVE_DEFAULT_ENDPOINT_PORT)
            )
        });

        let secret_layer = AuthClientLayer::new(auth_secret);
        let middleware = tower::ServiceBuilder::default().layer(secret_layer);

        let async_client: HttpClient<AuthClientService<HttpBackend>> = jsonrpsee::http_client::HttpClientBuilder::default()
            .set_http_middleware(middleware)
            .request_timeout(
                self.timeout
                    .unwrap_or(Duration::from_secs(ENCLAVE_DEFAULT_TIMEOUT_SECONDS)),
            )
            .build(url)
            .unwrap();
        
        EnclaveClient::new_from_client(async_client)
    }
}

/// A client for the enclave API.
#[derive(Debug, Clone)]
pub struct EnclaveClient {
    /// The inner HTTP client.
    async_client: HttpClient<AuthClientService<HttpBackend>>,
    /// The runtime for the client.
    handle: Handle,
}

impl Deref for EnclaveClient {
    type Target = HttpClient<AuthClientService<HttpBackend>>;

    fn deref(&self) -> &Self::Target {
        &self.async_client
    }
}

impl EnclaveClient {
    pub fn builder() -> EnclaveClientBuilder {
        EnclaveClientBuilder::new()
    }

    pub fn new_from_client(async_client: HttpClient<AuthClientService<HttpBackend>>) -> Self {
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
    pub fn mock_default() -> Self {
        let auth_secret = JwtSecret::mock_default();
        EnclaveClientBuilder::new()
            .auth_secret(auth_secret)
            .addr(ENCLAVE_DEFAULT_ENDPOINT_ADDR.to_string())
            .port(ENCLAVE_DEFAULT_ENDPOINT_PORT)
            .timeout(Duration::from_secs(ENCLAVE_DEFAULT_TIMEOUT_SECONDS))
            .build()
    }
}

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
    fn get_public_key(&self) -> Result<secp256k1::PublicKey, ClientError>,
    fn get_genesis_data(&self) -> Result<GenesisDataResponse, ClientError>,
    fn sign(&self, _req: Secp256k1SignRequest) -> Result<Secp256k1SignResponse, ClientError>,
    fn encrypt(&self, req: IoEncryptionRequest) -> Result<IoEncryptionResponse, ClientError>,
    fn decrypt(&self, req: IoDecryptionRequest) -> Result<IoDecryptionResponse, ClientError>,
    fn get_eph_rng_keypair(&self) -> Result<schnorrkel::keys::Keypair, ClientError>,
    fn get_attestation_evidence(&self, _req: AttestationGetEvidenceRequest) -> Result<AttestationGetEvidenceResponse, ClientError>,
    fn eval_attestation_evidence(&self, _req: AttestationEvalEvidenceRequest) -> Result<AttestationEvalEvidenceResponse, ClientError>,
);

#[cfg(test)]
pub mod tests {
    use crate::{
        get_unsecure_sample_secp256k1_pk, nonce::Nonce, rpc::BuildableServer, MockEnclaveServer,
    };

    use super::*;
    use secp256k1::{rand, Secp256k1};
    use std::{
        net::{SocketAddr, TcpListener},
        time::Duration,
    };
    use tokio::time::sleep;

    #[test]
    fn test_client_sync_context() {
        // testing if sync client can be created in a sync runtime
        let _ = EnclaveClient::mock_default();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sync_client() {
        // spawn a seperate thread for the server, otherwise the test will hang
        let port = get_random_port(); // rand port for test parallelization
        let addr = SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_ADDR, port));
        let _server_handle = MockEnclaveServer::new(addr).start().await.unwrap();
        let _ = sleep(Duration::from_secs(2));

        let client = EnclaveClient::mock_default();
        sync_test_health_check(&client);
        sync_test_get_public_key(&client);
        sync_test_get_eph_rng_keypair(&client);
        sync_test_tx_io_encrypt_decrypt(&client);
    }

    pub fn get_random_port() -> u16 {
        TcpListener::bind("127.0.0.1:0") // 0 means OS assigns a free port
            .expect("Failed to bind to a port")
            .local_addr()
            .unwrap()
            .port()
    }

    pub fn sync_test_tx_io_encrypt_decrypt<C: SyncEnclaveApiClient>(client: &C) {
        // make the request struct
        let secp = Secp256k1::new();
        let (_secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        let data_to_encrypt = vec![72, 101, 108, 108, 111];
        let nonce = Nonce::new_rand();
        let encryption_request = IoEncryptionRequest {
            key: public_key,
            data: data_to_encrypt.clone(),
            nonce: nonce.clone(),
        };

        // make the http request
        let encryption_response = client.encrypt(encryption_request).unwrap();

        // check the response
        assert!(!encryption_response.encrypted_data.is_empty());

        let decryption_request = IoDecryptionRequest {
            key: public_key,
            data: encryption_response.encrypted_data,
            nonce: nonce.clone(),
        };

        let decryption_response = client.decrypt(decryption_request).unwrap();
        assert_eq!(decryption_response.decrypted_data, data_to_encrypt);
    }

    pub fn sync_test_health_check<C: SyncEnclaveApiClient>(client: &C) {
        let resposne = client.health_check().unwrap();
        assert_eq!(resposne, "OK");
    }

    pub fn sync_test_get_public_key<C: SyncEnclaveApiClient>(client: &C) {
        let res = client.get_public_key().unwrap();
        assert_eq!(res, get_unsecure_sample_secp256k1_pk());
    }

    pub fn sync_test_get_eph_rng_keypair<C: SyncEnclaveApiClient>(client: &C) {
        let res = client.get_eph_rng_keypair().unwrap();
        println!("eph_rng_keypair: {:?}", res);
    }
}
