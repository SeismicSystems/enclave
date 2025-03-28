use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use anyhow::Result;
use jsonrpsee::{
    core::{async_trait, ClientError, RpcResult},
    server::ServerHandle,
    Methods,
};

use crate::{
    coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse},
    coco_as::{AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse},
    ecdh_decrypt, ecdh_encrypt,
    genesis::GenesisDataResponse,
    get_unsecure_sample_schnorrkel_keypair, get_unsecure_sample_secp256k1_pk,
    get_unsecure_sample_secp256k1_sk,
    signing::{
        Secp256k1SignRequest, Secp256k1SignResponse
    },
    tx_io::{IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse},
};

use super::{
    rpc::{BuildableServer, EnclaveApiServer, SyncEnclaveApiClient},
    ENCLAVE_DEFAULT_ENDPOINT_ADDR, ENCLAVE_DEFAULT_ENDPOINT_PORT,
};
use reth_rpc_layer::JwtSecret;

pub struct MockEnclaveServer {
    addr: SocketAddr,
}

impl MockEnclaveServer {
    pub fn new(addr: impl Into<SocketAddr>) -> Self {
        Self { addr: addr.into() }
    }

    pub fn new_from_addr_port(addr: String, port: u16) -> Self {
        Self::new((IpAddr::from_str(&addr).unwrap(), port))
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
}

impl Default for MockEnclaveServer {
    fn default() -> Self {
        Self::new((ENCLAVE_DEFAULT_ENDPOINT_ADDR, ENCLAVE_DEFAULT_ENDPOINT_PORT))
    }
}

impl BuildableServer for MockEnclaveServer {
    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn methods(self) -> Methods {
        self.into_rpc().into()
    }

    fn auth_secret(&self) -> reth_rpc_layer::JwtSecret {
        JwtSecret::from_str("0x00").unwrap()
    }

    async fn start(self) -> Result<ServerHandle> {
        BuildableServer::start_rpc_server(self).await
    }
}

#[async_trait]
impl EnclaveApiServer for MockEnclaveServer {
    /// Handler for: `getPublicKey`
    async fn get_public_key(&self) -> RpcResult<secp256k1::PublicKey> {
        Ok(MockEnclaveServer::get_public_key())
    }

    /// Handler for: `healthCheck`
    async fn health_check(&self) -> RpcResult<String> {
        Ok(MockEnclaveServer::health_check())
    }

    /// Handler for: `getGenesisData`
    async fn get_genesis_data(&self) -> RpcResult<GenesisDataResponse> {
        Ok(MockEnclaveServer::get_genesis_data())
    }

    /// Handler for: `encrypt`
    async fn encrypt(&self, req: IoEncryptionRequest) -> RpcResult<IoEncryptionResponse> {
        Ok(MockEnclaveServer::encrypt(req))
    }

    /// Handler for: `decrypt`
    async fn decrypt(&self, req: IoDecryptionRequest) -> RpcResult<IoDecryptionResponse> {
        Ok(MockEnclaveServer::decrypt(req))
    }

    /// Handler for: `getAttestationEvidence`
    async fn get_attestation_evidence(
        &self,
        req: AttestationGetEvidenceRequest,
    ) -> RpcResult<AttestationGetEvidenceResponse> {
        Ok(MockEnclaveServer::get_attestation_evidence(req))
    }

    /// Handler for: `evalAttestationEvidence`
    async fn eval_attestation_evidence(
        &self,
        req: AttestationEvalEvidenceRequest,
    ) -> RpcResult<AttestationEvalEvidenceResponse> {
        Ok(MockEnclaveServer::eval_attestation_evidence(req))
    }

    /// Handler for: `sign`
    async fn sign(&self, req: Secp256k1SignRequest) -> RpcResult<Secp256k1SignResponse> {
        Ok(MockEnclaveServer::sign(req))
    }

    /// Handler for: 'eph_rng.get_keypair'
    async fn get_eph_rng_keypair(&self) -> RpcResult<schnorrkel::keys::Keypair> {
        Ok(MockEnclaveServer::get_eph_rng_keypair())
    }

}

pub struct MockEnclaveClient;
impl MockEnclaveClient {
    pub fn new() -> Self {
        Self {}
    }
}

macro_rules! impl_mock_sync_client_trait {
    ($(fn $method_name:ident(&self $(, $param:ident: $param_ty:ty)*) -> $return_ty:ty),* $(,)?) => {
        impl SyncEnclaveApiClient for MockEnclaveClient {
            $(
                fn $method_name(&self, $($param: $param_ty),*) -> $return_ty {
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
    fn encrypt(&self, req: IoEncryptionRequest) -> Result<IoEncryptionResponse, ClientError>,
    fn decrypt(&self, req: IoDecryptionRequest) -> Result<IoDecryptionResponse, ClientError>,
    fn get_eph_rng_keypair(&self) -> Result<schnorrkel::keys::Keypair, ClientError>,
    fn get_attestation_evidence(&self, _req: AttestationGetEvidenceRequest) -> Result<AttestationGetEvidenceResponse, ClientError>,
    fn eval_attestation_evidence(&self, _req: AttestationEvalEvidenceRequest) -> Result<AttestationEvalEvidenceResponse, ClientError>,
);

#[cfg(test)]
mod tests {
    use std::{ops::Deref, time::Duration};

    use secp256k1::{rand, Secp256k1};
    use tokio::time::sleep;

    use super::*;
    use crate::{client::tests::*, nonce::Nonce, rpc::EnclaveApiClient, EnclaveClient};

    #[test]
    fn test_mock_client() {
        let client = MockEnclaveClient {};
        sync_test_health_check(&client);
        sync_test_get_public_key(&client);
        sync_test_get_eph_rng_keypair(&client);
        sync_test_tx_io_encrypt_decrypt(&client);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_mock_server_and_sync_client() {
        // spawn a seperate thread for the server, otherwise the test will hang
        let addr = SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_ADDR, ENCLAVE_DEFAULT_ENDPOINT_PORT));
        println!("addr: {:?}", addr);
        let _server_handle = MockEnclaveServer::new(addr).start().await.unwrap();
        let _ = sleep(Duration::from_secs(2));

        let client = EnclaveClient::mock_default();
        async_test_health_check(&client).await;
        async_test_get_public_key(&client).await;
        async_test_get_eph_rng_keypair(&client).await;
        async_test_tx_io_encrypt_decrypt(&client).await;
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
