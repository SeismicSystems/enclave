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
        Secp256k1SignRequest, Secp256k1SignResponse, Secp256k1VerifyRequest,
        Secp256k1VerifyResponse,
    },
    snapsync::{SnapSyncRequest, SnapSyncResponse},
    tx_io::{IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse},
};

use super::{
    rpc::{BuildableServer, EnclaveApiServer, SyncEnclaveApiClient},
    ENCLAVE_DEFAULT_ENDPOINT_ADDR, ENCLAVE_DEFAULT_ENDPOINT_PORT,
};

pub struct MockEnclaveClient;

impl MockEnclaveClient {
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
}

impl SyncEnclaveApiClient for MockEnclaveClient {
    fn health_check(&self) -> Result<String, ClientError> {
        Ok(MockEnclaveClient::health_check())
    }

    fn get_eph_rng_keypair(&self) -> Result<schnorrkel::keys::Keypair, ClientError> {
        Ok(MockEnclaveClient::get_eph_rng_keypair())
    }

    fn encrypt(&self, req: IoEncryptionRequest) -> Result<IoEncryptionResponse, ClientError> {
        Ok(MockEnclaveClient::encrypt(req))
    }

    fn decrypt(&self, req: IoDecryptionRequest) -> Result<IoDecryptionResponse, ClientError> {
        Ok(MockEnclaveClient::decrypt(req))
    }

    fn get_public_key(&self) -> Result<secp256k1::PublicKey, ClientError> {
        Ok(MockEnclaveClient::get_public_key())
    }

    fn get_genesis_data(&self) -> Result<GenesisDataResponse, ClientError> {
        unimplemented!("genesis_get_data not implemented for mock server")
    }

    fn get_snapsync_backup(&self, _req: SnapSyncRequest) -> Result<SnapSyncResponse, ClientError> {
        unimplemented!("provide_snapsync_backup not implemented for mock server")
    }

    fn sign(&self, _req: Secp256k1SignRequest) -> Result<Secp256k1SignResponse, ClientError> {
        unimplemented!("secp256k1_sign not implemented for mock server")
    }

    fn verify(&self, _req: Secp256k1VerifyRequest) -> Result<Secp256k1VerifyResponse, ClientError> {
        unimplemented!("secp256k1_verify not implemented for mock server")
    }

    fn get_attestation_evidence(
        &self,
        _req: AttestationGetEvidenceRequest,
    ) -> Result<AttestationGetEvidenceResponse, ClientError> {
        unimplemented!("attestation_get_evidence not implemented for mock server")
    }

    fn eval_attestation_evidence(
        &self,
        _req: AttestationEvalEvidenceRequest,
    ) -> Result<AttestationEvalEvidenceResponse, ClientError> {
        unimplemented!("attestation_eval_evidence not implemented for mock server")
    }
}

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

    async fn start(self) -> Result<ServerHandle> {
        BuildableServer::start_rpc_server(self).await
    }
}

#[async_trait]
impl EnclaveApiServer for MockEnclaveServer {
    async fn get_public_key(&self) -> RpcResult<secp256k1::PublicKey> {
        Ok(MockEnclaveClient::get_public_key())
    }

    async fn health_check(&self) -> RpcResult<String> {
        Ok(MockEnclaveClient::health_check())
    }

    async fn get_genesis_data(&self) -> RpcResult<GenesisDataResponse> {
        unimplemented!("genesis_get_data not implemented for mock server")
    }

    async fn get_snapsync_backup(&self, _request: SnapSyncRequest) -> RpcResult<SnapSyncResponse> {
        unimplemented!("provide_snapsync_backup not implemented for mock server")
    }

    async fn sign(&self, _req: Secp256k1SignRequest) -> RpcResult<Secp256k1SignResponse> {
        unimplemented!("secp256k1_sign not implemented for mock server")
    }

    async fn verify(&self, _req: Secp256k1VerifyRequest) -> RpcResult<Secp256k1VerifyResponse> {
        unimplemented!("secp256k1_verify not implemented for mock server")
    }

    async fn get_attestation_evidence(
        &self,
        _req: AttestationGetEvidenceRequest,
    ) -> RpcResult<AttestationGetEvidenceResponse> {
        unimplemented!("attestation_get_evidence not implemented for mock server")
    }

    async fn eval_attestation_evidence(
        &self,
        _req: AttestationEvalEvidenceRequest,
    ) -> RpcResult<AttestationEvalEvidenceResponse> {
        unimplemented!("attestation_eval_evidence not implemented for mock server")
    }

    async fn encrypt(&self, request: IoEncryptionRequest) -> RpcResult<IoEncryptionResponse> {
        Ok(MockEnclaveClient::encrypt(request))
    }

    async fn decrypt(&self, request: IoDecryptionRequest) -> RpcResult<IoDecryptionResponse> {
        Ok(MockEnclaveClient::decrypt(request))
    }

    async fn get_eph_rng_keypair(&self) -> RpcResult<schnorrkel::keys::Keypair> {
        Ok(MockEnclaveClient::get_eph_rng_keypair())
    }
}

#[cfg(test)]
mod tests {
    use std::{ops::Deref, time::Duration};

    use secp256k1::{rand, Secp256k1};
    use tokio::time::sleep;

    use super::*;
    use crate::{client::tests::*, rpc::EnclaveApiClient, EnclaveClient};

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
        let port = get_random_port();
        let addr = SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_ADDR, port));
        println!("addr: {:?}", addr);
        let _server_handle = MockEnclaveServer::new(addr).start().await.unwrap();
        let _ = sleep(Duration::from_secs(2));

        let client = EnclaveClient::new(format!("http://{}:{}", addr.ip(), addr.port()));
        test_health_check(&client).await;
        test_get_public_key(&client).await;
        test_get_eph_rng_keypair(&client).await;
        test_tx_io_encrypt_decrypt(&client).await;
    }

    async fn test_tx_io_encrypt_decrypt(client: &EnclaveClient) {
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
        let encryption_response = client.deref().encrypt(encryption_request).await.unwrap();

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

    async fn test_health_check(client: &EnclaveClient) {
        let resposne = client.deref().health_check().await.unwrap();
        assert_eq!(resposne, "OK");
    }

    async fn test_get_public_key(client: &EnclaveClient) {
        let res = client.deref().get_public_key().await.unwrap();
        assert_eq!(res, get_unsecure_sample_secp256k1_pk());
    }

    async fn test_get_eph_rng_keypair(client: &EnclaveClient) {
        let res = client.deref().get_eph_rng_keypair().await.unwrap();
        println!("eph_rng_keypair: {:?}", res);
    }
}
