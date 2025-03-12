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

#[test]
fn test_mock_client() {
    let client = MockEnclaveClient {};
    let res = client.health_check().unwrap();
    assert_eq!(res, "OK");
}
