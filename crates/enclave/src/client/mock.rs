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
use crate::{
    boot::{
        RetrieveRootKeyRequest, RetrieveRootKeyResponse, ShareRootKeyRequest, ShareRootKeyResponse,
    },
    coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse},
    coco_as::{AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse},
    ecdh_encrypt, get_unsecure_sample_schnorrkel_keypair, get_unsecure_sample_secp256k1_pk,
    get_unsecure_sample_secp256k1_sk,
    keys::{GetPurposeKeysRequest, GetPurposeKeysResponse},
    nonce::Nonce,
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

    /// Mock implementation of the get_public_key method.
    pub fn get_purpose_keys(_req: GetPurposeKeysRequest) -> GetPurposeKeysResponse {
        GetPurposeKeysResponse {
            tx_io_sk: get_unsecure_sample_secp256k1_sk(),
            tx_io_pk: get_unsecure_sample_secp256k1_pk(),
            snapshot_key_bytes: [0u8; 32],
            rng_keypair: get_unsecure_sample_schnorrkel_keypair(),
        }
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
    async fn get_purpose_keys(&self, req: GetPurposeKeysRequest) -> GetPurposeKeysResponse,
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
    fn get_purpose_keys(&self, _req: GetPurposeKeysRequest) -> Result<GetPurposeKeysResponse, ClientError>,
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
    use tokio::time::sleep;

    use super::*;
    use crate::client::tests::*;
    use crate::{rpc::EnclaveApiClient, EnclaveClient};

    #[test]
    fn test_mock_client() {
        let client = MockEnclaveClient {};
        sync_test_health_check(&client);
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
        Ok(())
    }

    async fn async_test_health_check(client: &EnclaveClient) {
        let resposne = client.deref().health_check().await.unwrap();
        assert_eq!(resposne, "OK");
    }
}
