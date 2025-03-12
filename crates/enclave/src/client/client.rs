use jsonrpsee::{core::ClientError, http_client::HttpClient};
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr},
    ops::Deref,
    sync::OnceLock,
};
use tokio::runtime::{Handle, Runtime};

use crate::{
    coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse},
    coco_as::{AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse},
    genesis::GenesisDataResponse,
    signing::{
        Secp256k1SignRequest, Secp256k1SignResponse, Secp256k1VerifyRequest,
        Secp256k1VerifyResponse,
    },
    snapsync::{SnapSyncRequest, SnapSyncResponse},
    tx_io::{IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse},
};

use super::rpc::{EnclaveApiClient, SyncEnclaveApiClient};

pub const ENCLAVE_DEFAULT_ENDPOINT_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
pub const ENCLAVE_DEFAULT_ENDPOINT_PORT: u16 = 7878;

static ENCLAVE_CLIENT_RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// A client for the enclave API.
#[derive(Debug)]
pub struct EnclaveClient {
    /// The inner HTTP client.
    async_client: HttpClient,
    /// The runtime for the client.
    handle: Handle,
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
        let handle = Handle::try_current().unwrap_or_else(|_| {
            let runtime = ENCLAVE_CLIENT_RUNTIME.get_or_init(|| Runtime::new().unwrap());
            runtime.handle().clone()
        });
        Self {
            async_client: inner,
            handle,
        }
    }

    /// Create a new enclave client from an address and port.
    pub fn new_from_addr_port(addr: impl Into<String>, port: u16) -> Self {
        Self::new(format!("http://{}:{}", addr.into(), port))
    }

    /// Block on a future with the runtime.
    pub fn block_on_with_runtime<F, T>(&self, future: F) -> T
    where
        F: Future<Output = T>,
    {
        tokio::task::block_in_place(|| self.handle.block_on(future))
    }
}

macro_rules! impl_sync_client {
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

impl_sync_client!(
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
);

#[cfg(test)]
pub mod tests {
    use crate::{get_unsecure_sample_secp256k1_pk, rpc::BuildableServer, MockEnclaveServer};

    use super::*;
    use secp256k1::{rand, Secp256k1};
    use std::{
        net::{SocketAddr, TcpListener},
        time::Duration,
    };
    use tokio::time::sleep;

    #[test]
    fn test_client_sync_context() {
        let port = 1888;
        let addr = SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_ADDR, port));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sync_client() {
        // spawn a seperate thread for the server, otherwise the test will hang
        let port = get_random_port();
        let addr = SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_ADDR, port));
        println!("addr: {:?}", addr);
        let _server_handle = MockEnclaveServer::new(addr).start().await.unwrap();
        sleep(Duration::from_secs(2));

        let client = EnclaveClient::new(format!("http://{}:{}", addr.ip(), addr.port()));
        sync_test_health_check(&client);
        sync_test_get_public_key(&client);
        sync_test_get_eph_rng_keypair(&client);
        sync_test_tx_io_encrypt_decrypt(&client);
    }

    #[tokio::test]
    async fn test_async_client() {
        // spawn a seperate thread for the server, otherwise the test will hang
        let port = get_random_port();
        let addr = SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_ADDR, port));
        println!("addr: {:?}", addr);
        let _server_handle = MockEnclaveServer::new(addr).start().await.unwrap();
        sleep(Duration::from_secs(2));
        let client = EnclaveClient::new(format!("http://{}:{}", addr.ip(), addr.port()));

        test_health_check(&client).await;
        test_tx_io_encrypt_decrypt(&client).await;
        test_get_public_key(&client).await;
        test_get_eph_rng_keypair(&client).await;
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
        let mut nonce = vec![0u8; 4]; // 4 leading zeros
        nonce.extend_from_slice(&(12345678u64).to_be_bytes()); // Append the 8-byte u64
        let encryption_request = IoEncryptionRequest {
            key: public_key,
            data: data_to_encrypt.clone(),
            nonce: nonce.clone().into(),
        };

        // make the http request
        let encryption_response = client.encrypt(encryption_request).unwrap();

        // check the response
        assert!(!encryption_response.encrypted_data.is_empty());

        let decryption_request = IoDecryptionRequest {
            key: public_key,
            data: encryption_response.encrypted_data,
            nonce: nonce.into(),
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
