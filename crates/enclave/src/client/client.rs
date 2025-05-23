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
use crate::{
    coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse},
    coco_as::{AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse},
    genesis::GenesisDataResponse,
    signing::{
        Secp256k1SignRequest, Secp256k1SignResponse, Secp256k1VerifyRequest,
        Secp256k1VerifyResponse,
    },
    snapshot::{
        PrepareEncryptedSnapshotRequest, PrepareEncryptedSnapshotResponse,
        RestoreFromEncryptedSnapshotRequest, RestoreFromEncryptedSnapshotResponse,
    },
    snapsync::{SnapSyncRequest, SnapSyncResponse},
    tx_io::{IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse},
};

pub const ENCLAVE_DEFAULT_ENDPOINT_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
pub const ENCLAVE_DEFAULT_ENDPOINT_PORT: u16 = 7878;
pub const ENCLAVE_DEFAULT_TIMEOUT_SECONDS: u64 = 5;
static ENCLAVE_CLIENT_RUNTIME: OnceLock<Runtime> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct EnclaveClientBuilder {
    addr: Option<String>,
    port: Option<u16>,
    timeout: Option<Duration>,
    url: Option<String>,
}

impl EnclaveClientBuilder {
    pub fn new() -> Self {
        Self {
            addr: None,
            port: None,
            timeout: None,
            url: None,
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

    pub fn build(self) -> EnclaveClient {
        let url = self.url.unwrap_or_else(|| {
            format!(
                "http://{}:{}",
                self.addr
                    .unwrap_or_else(|| ENCLAVE_DEFAULT_ENDPOINT_ADDR.to_string()),
                self.port.unwrap_or(ENCLAVE_DEFAULT_ENDPOINT_PORT)
            )
        });
        let async_client = jsonrpsee::http_client::HttpClientBuilder::default()
            .request_timeout(
                self.timeout
                    .unwrap_or(Duration::from_secs(ENCLAVE_DEFAULT_TIMEOUT_SECONDS)),
            )
            .build(url)
            .unwrap();
        EnclaveClient::new_from_client(async_client)
    }
}

impl Default for EnclaveClientBuilder {
    fn default() -> Self {
        let mut builder = EnclaveClientBuilder::new();

        let url = format!(
            "http://{}:{}",
            ENCLAVE_DEFAULT_ENDPOINT_ADDR, ENCLAVE_DEFAULT_ENDPOINT_PORT
        );
        builder = builder.url(url);
        builder = builder.timeout(Duration::from_secs(5));
        builder
    }
}

impl SyncEnclaveApiClientBuilder for EnclaveClientBuilder {
    type Client = EnclaveClient;
    fn build(self) -> EnclaveClient {
        EnclaveClientBuilder::build(self)
    }
}

/// A client for the enclave API.
#[derive(Debug, Clone)]
pub struct EnclaveClient {
    /// The inner HTTP client.
    async_client: HttpClient,
    /// The runtime for the client.
    handle: Handle,
}

impl Default for EnclaveClient {
    fn default() -> Self {
        let default_builder = EnclaveClientBuilder::default();
        default_builder.build()
    }
}

impl Deref for EnclaveClient {
    type Target = HttpClient;

    fn deref(&self) -> &Self::Target {
        &self.async_client
    }
}

impl EnclaveClient {
    pub fn builder() -> EnclaveClientBuilder {
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

    pub fn new_from_client(async_client: HttpClient) -> Self {
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
    fn get_snapsync_backup(&self, _req: SnapSyncRequest) -> Result<SnapSyncResponse, ClientError>,
    fn sign(&self, _req: Secp256k1SignRequest) -> Result<Secp256k1SignResponse, ClientError>,
    fn encrypt(&self, req: IoEncryptionRequest) -> Result<IoEncryptionResponse, ClientError>,
    fn decrypt(&self, req: IoDecryptionRequest) -> Result<IoDecryptionResponse, ClientError>,
    fn get_eph_rng_keypair(&self) -> Result<schnorrkel::keys::Keypair, ClientError>,
    fn verify(&self, _req: Secp256k1VerifyRequest) -> Result<Secp256k1VerifyResponse, ClientError>,
    fn get_attestation_evidence(&self, _req: AttestationGetEvidenceRequest) -> Result<AttestationGetEvidenceResponse, ClientError>,
    fn eval_attestation_evidence(&self, _req: AttestationEvalEvidenceRequest) -> Result<AttestationEvalEvidenceResponse, ClientError>,
    fn prepare_encrypted_snapshot(&self, _req: PrepareEncryptedSnapshotRequest) -> Result<PrepareEncryptedSnapshotResponse, ClientError>,
    fn restore_from_encrypted_snapshot(&self, _req: RestoreFromEncryptedSnapshotRequest) -> Result<RestoreFromEncryptedSnapshotResponse, ClientError>,
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
        let port = 1888;
        let addr = SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_ADDR, port));
        let _ = EnclaveClient::new(format!("http://{}:{}", addr.ip(), addr.port()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sync_client() {
        // spawn a seperate thread for the server, otherwise the test will hang
        let port = get_random_port();
        let addr = SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_ADDR, port));
        println!("addr: {:?}", addr);
        let _server_handle = MockEnclaveServer::new(addr).start().await.unwrap();
        let _ = sleep(Duration::from_secs(2));

        let client = EnclaveClient::new(format!("http://{}:{}", addr.ip(), addr.port()));
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
