//! A mock enclave server for testing purposes.

use anyhow::Result;
use jsonrpsee::{
    core::{async_trait, ClientError, RpcResult},
    server::ServerHandle,
    Methods,
};
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use super::{
    rpc::{BuildableServer, EnclaveApiServer, SyncEnclaveApiClient},
    ENCLAVE_DEFAULT_ENDPOINT_IP, ENCLAVE_DEFAULT_ENDPOINT_PORT,
};
use crate::nonce::Nonce;
use crate::{
    boot::{
        RetrieveRootKeyRequest, RetrieveRootKeyResponse, ShareRootKeyRequest, ShareRootKeyResponse,
    },
    coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse},
    coco_as::{AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse},
    ecdh_decrypt, ecdh_encrypt,
    genesis::GenesisDataResponse,
    get_unsecure_sample_schnorrkel_keypair, get_unsecure_sample_secp256k1_pk,
    get_unsecure_sample_secp256k1_sk,
    signing::{
        Secp256k1SignRequest, Secp256k1SignResponse, Secp256k1VerifyRequest,
        Secp256k1VerifyResponse,
    },
    tx_io::{IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse},
};

/// A mock enclave server for testing purposes.
/// Does not check the validity of the JWT token.
pub struct MockEnclaveServer {
    addr: SocketAddr,
}

impl MockEnclaveServer {
    pub fn new(addr: impl Into<SocketAddr>) -> Self {
        Self { addr: addr.into() }
    }

    pub fn new_from_ip_port(ip: String, port: u16) -> Self {
        Self::new((IpAddr::from_str(&ip).unwrap(), port))
    }

    /// Mock implementation of the health check method.
    pub fn health_check() -> String {
        "OK".to_string()
    }

    /// Mock implementation of the get_eph_rng_keypair method.
    pub fn get_eph_rng_keypair() -> schnorrkel::keys::Keypair {
        // Return a sample Schnorrkel keypair for testing
        get_unsecure_sample_schnorrkel_keypair()
    }

    /// Mock implementation of the encrypt method.
    pub fn encrypt(req: IoEncryptionRequest) -> IoEncryptionResponse {
        // Use the sample secret key for encryption
        let encrypted_data = ecdh_encrypt(
            &req.key,
            &get_unsecure_sample_secp256k1_sk(),
            &req.data,
            req.nonce,
        )
        .unwrap();

        IoEncryptionResponse { encrypted_data }
    }

    /// Mock implementation of the decrypt method.
    pub fn decrypt(req: IoDecryptionRequest) -> IoDecryptionResponse {
        // Use the sample secret key for decryption
        let decrypted_data = ecdh_decrypt(
            &req.key,
            &get_unsecure_sample_secp256k1_sk(),
            &req.data,
            req.nonce,
        )
        .unwrap();

        IoDecryptionResponse { decrypted_data }
    }

    /// Mock implementation of the get_public_key method.
    pub fn get_public_key() -> secp256k1::PublicKey {
        get_unsecure_sample_secp256k1_pk()
    }

    /// Mock implementation of the sign method.
    pub fn sign(_req: Secp256k1SignRequest) -> Secp256k1SignResponse {
        unimplemented!("sign not implemented for mock server")
    }

    /// Mock implementation of the verify method.
    pub fn verify(_req: Secp256k1VerifyRequest) -> Secp256k1VerifyResponse {
        unimplemented!("verify not implemented for mock server")
    }

    /// Mock implementation of the get_genesis_data method.
    pub fn get_genesis_data() -> GenesisDataResponse {
        unimplemented!("get_genesis_data not implemented for mock server")
    }

    /// Mock implementation of the get_attestation_evidence method.
    pub fn get_attestation_evidence(
        _req: AttestationGetEvidenceRequest,
    ) -> AttestationGetEvidenceResponse {
        unimplemented!("get_attestation_evidence not implemented for mock server")
    }

    /// Mock implementation of the eval_attestation_evidence method.
    pub fn eval_attestation_evidence(
        _req: AttestationEvalEvidenceRequest,
    ) -> AttestationEvalEvidenceResponse {
        unimplemented!("eval_attestation_evidence not implemented for mock server")
    }

    fn boot_retrieve_root_key(_req: RetrieveRootKeyRequest) -> RetrieveRootKeyResponse {
        // No-op, keys are hardcoded for mock server
        RetrieveRootKeyResponse {}
    }

    fn boot_share_root_key(req: ShareRootKeyRequest) -> ShareRootKeyResponse {
        // skip checking the attestation since it's a mock

        // encrypt the root key
        let sharer_sk = get_unsecure_sample_secp256k1_sk();
        let sharer_pk = get_unsecure_sample_secp256k1_pk();
        let mock_root_key = [0u8; 32];
        let nonce = Nonce::new_rand();

        let root_key_ciphertext =
            ecdh_encrypt(&req.retriever_pk, &sharer_sk, &mock_root_key, nonce.clone()).unwrap();

        ShareRootKeyResponse {
            nonce,
            root_key_ciphertext,
            sharer_pk,
        }
    }

    fn boot_genesis() {
        // No-op, keys are hardcoded for mock server
    }

    fn complete_boot() {
        // No-op, keys are hardcoded for mock server
    }
}

impl Default for MockEnclaveServer {
    fn default() -> Self {
        Self::new((ENCLAVE_DEFAULT_ENDPOINT_IP, ENCLAVE_DEFAULT_ENDPOINT_PORT))
    }
}

impl BuildableServer for MockEnclaveServer {
    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn methods(self) -> Methods {
        self.into_rpc().into()
    }

    async fn start(self) -> Result<ServerHandle> {
        BuildableServer::start_rpc_server(self).await
    }
}

/// Derive implementation of the async [`EnclaveApiServer`] trait
/// for [`MockEnclaveServer`]
macro_rules! impl_mock_async_server_trait {
    ($(async fn $method_name:ident(&self $(, $param:ident: $param_ty:ty)*)
        -> $ret:ty),* $(,)?) => {
        #[async_trait]
        impl EnclaveApiServer for MockEnclaveServer {
            $(
                async fn $method_name(&self $(, $param: $param_ty)*) -> RpcResult<$ret> {
                    // For each method, call the corresponding method on the mock server
                    Ok(MockEnclaveServer::$method_name($($param),*))
                }
            )*
        }
    };
}
impl_mock_async_server_trait!(
    async fn health_check(&self) -> String,
    async fn get_public_key(&self) -> secp256k1::PublicKey,
    async fn get_genesis_data(&self) -> GenesisDataResponse,
    async fn sign(&self, req: Secp256k1SignRequest) -> Secp256k1SignResponse,
    async fn verify(&self, req: Secp256k1VerifyRequest) -> Secp256k1VerifyResponse,
    async fn encrypt(&self, req: IoEncryptionRequest) -> IoEncryptionResponse,
    async fn decrypt(&self, req: IoDecryptionRequest) -> IoDecryptionResponse,
    async fn get_eph_rng_keypair(&self) -> schnorrkel::keys::Keypair,
    async fn get_attestation_evidence(&self, req: AttestationGetEvidenceRequest) -> AttestationGetEvidenceResponse,
    async fn eval_attestation_evidence(&self, req: AttestationEvalEvidenceRequest) -> AttestationEvalEvidenceResponse,
    async fn boot_retrieve_root_key(&self, req: RetrieveRootKeyRequest) -> RetrieveRootKeyResponse,
    async fn boot_share_root_key(&self, req: ShareRootKeyRequest) -> ShareRootKeyResponse,
    async fn boot_genesis(&self) -> (),
    async fn complete_boot(&self) -> (),
);

/// Mock enclave client for testing purposes.
/// Useful for testing the against the mock server,
/// as it can be easily set up instead of going through the EnclaveClientBuilder
pub struct MockEnclaveClient;
impl Default for MockEnclaveClient {
    fn default() -> Self {
        Self::new()
    }
}
impl MockEnclaveClient {
    pub fn new() -> Self {
        Self {}
    }
}

/// Derive implementation of the [`SyncEnclaveApiClient`] trait
/// for [`MockEnclaveClient`].
/// based on functions implemented in the [`MockEnclaveServer`].
macro_rules! impl_mock_sync_client_trait {
    ($(fn $method_name:ident(&self $(, $param:ident: $param_ty:ty)*) -> $return_ty:ty),* $(,)?) => {
        impl SyncEnclaveApiClient for MockEnclaveClient {
            $(
                fn $method_name(&self, $($param: $param_ty),*) -> $return_ty {
                    // for each method, call the corresponding method on the mock server
                    // simulates a client client rpc call where that code is executed
                    Ok(MockEnclaveServer::$method_name($($param),*))
                }
            )+
        }
    };
}
impl_mock_sync_client_trait!(
    fn health_check(&self) -> Result<String, ClientError>,
    fn get_public_key(&self) -> Result<secp256k1::PublicKey, ClientError>,
    fn get_genesis_data(&self) -> Result<GenesisDataResponse, ClientError>,
    fn sign(&self, _req: Secp256k1SignRequest) -> Result<Secp256k1SignResponse, ClientError>,
    fn verify(&self, _req: Secp256k1VerifyRequest) -> Result<Secp256k1VerifyResponse, ClientError>,
    fn encrypt(&self, req: IoEncryptionRequest) -> Result<IoEncryptionResponse, ClientError>,
    fn decrypt(&self, req: IoDecryptionRequest) -> Result<IoDecryptionResponse, ClientError>,
    fn get_eph_rng_keypair(&self) -> Result<schnorrkel::keys::Keypair, ClientError>,
    fn get_attestation_evidence(&self, _req: AttestationGetEvidenceRequest) -> Result<AttestationGetEvidenceResponse, ClientError>,
    fn eval_attestation_evidence(&self, _req: AttestationEvalEvidenceRequest) -> Result<AttestationEvalEvidenceResponse, ClientError>,
    fn boot_retrieve_root_key(&self, _req: RetrieveRootKeyRequest) -> Result<RetrieveRootKeyResponse,  ClientError>,
    fn boot_share_root_key(&self, _req: ShareRootKeyRequest) -> Result<ShareRootKeyResponse,  ClientError>,
    fn boot_genesis(&self) -> Result<(),  ClientError>,
    fn complete_boot(&self) -> Result<(),  ClientError>,
);

#[cfg(test)]
mod tests {
    use std::{ops::Deref, time::Duration};

    use secp256k1::{rand, Secp256k1};
    use tokio::time::sleep;

    use super::*;
    use crate::client::tests::*;
    use crate::{nonce::Nonce, rpc::EnclaveApiClient, EnclaveClient};

    #[test]
    fn test_mock_client() {
        let client = MockEnclaveClient {};
        sync_test_health_check(&client);
        sync_test_get_public_key(&client);
        sync_test_get_eph_rng_keypair(&client);
        sync_test_tx_io_encrypt_decrypt(&client);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_mock_server_and_sync_client() -> Result<()> {
        // spawn a seperate thread for the server, otherwise the test will hang
        let port = get_random_port();
        let addr = SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_IP, port));
        let _server_handle = MockEnclaveServer::new(addr).start().await?;
        let _ = sleep(Duration::from_secs(2)).await;

        let client = EnclaveClient::mock(addr.ip().to_string(), addr.port())?;
        async_test_health_check(&client).await;
        async_test_get_public_key(&client).await;
        async_test_get_eph_rng_keypair(&client).await;
        async_test_tx_io_encrypt_decrypt(&client).await;
        Ok(())
    }

    async fn async_test_tx_io_encrypt_decrypt(client: &EnclaveClient) {
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
        let encryption_response = client.deref().encrypt(encryption_request).await.unwrap();

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

    async fn async_test_health_check(client: &EnclaveClient) {
        let resposne = client.deref().health_check().await.unwrap();
        assert_eq!(resposne, "OK");
    }

    async fn async_test_get_public_key(client: &EnclaveClient) {
        let res = client.deref().get_public_key().await.unwrap();
        assert_eq!(res, get_unsecure_sample_secp256k1_pk());
    }

    async fn async_test_get_eph_rng_keypair(client: &EnclaveClient) {
        let res = client.deref().get_eph_rng_keypair().await.unwrap();
        println!("eph_rng_keypair: {:?}", res);
    }
}
