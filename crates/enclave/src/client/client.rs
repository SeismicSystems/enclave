use jsonrpsee::{
    core::{ClientError, RpcResult},
    http_client::HttpClient,
    types::{ErrorCode, ErrorObject, ErrorObjectOwned},
};
use std::{
    net::{IpAddr, Ipv4Addr},
    ops::Deref,
};
use tokio::runtime::Runtime;

use crate::{
    coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse},
    coco_as::{AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse},
    ecdh_decrypt, ecdh_encrypt,
    genesis::GenesisDataResponse,
    get_unsecure_sample_schnorrkel_keypair, get_unsecure_sample_secp256k1_pk,
    get_unsecure_sample_secp256k1_sk, rpc_invalid_ciphertext_error,
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

/// A client for the enclave API.
#[derive(Debug)]
pub struct EnclaveClient {
    /// The inner HTTP client.
    async_client: HttpClient,
    /// The runtime for the client.
    runtime: Runtime,
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
        Self {
            async_client: inner,
            runtime: Runtime::new().unwrap(),
        }
    }

    /// Create a new enclave client from an address and port.
    pub fn new_from_addr_port(addr: impl Into<String>, port: u16) -> Self {
        Self::new(format!("http://{}:{}", addr.into(), port))
    }
}

macro_rules! impl_sync_client {
    ($(fn $method_name:ident(&self $(, $param:ident: $param_ty:ty)*) -> $return_ty:ty),* $(,)?) => {
        impl SyncEnclaveApiClient for EnclaveClient {
            $(
                fn $method_name(&self, $($param: $param_ty),*) -> $return_ty {
                    self.runtime.block_on(self.async_client.$method_name($($param),*))
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

struct MockEnclaveClient;

impl SyncEnclaveApiClient for MockEnclaveClient {
    fn health_check(&self) -> Result<String, RpcError> {
        Ok("OK".to_string())
    }

    fn get_eph_rng_keypair(&self) -> Result<schnorrkel::keys::Keypair, RpcError> {
        // Return a sample Schnorrkel keypair for testing
        Ok(get_unsecure_sample_schnorrkel_keypair())
    }

    fn encrypt(&self, req: IoEncryptionRequest) -> Result<IoEncryptionResponse, RpcError> {
        // Use the sample secret key for encryption
        let encrypted_data = ecdh_encrypt(
            &req.key,
            &get_unsecure_sample_secp256k1_sk(),
            &req.data,
            req.nonce,
        )
        .unwrap();

        Ok(IoEncryptionResponse { encrypted_data })
    }

    fn decrypt(&self, req: IoDecryptionRequest) -> Result<IoDecryptionResponse, RpcError> {
        // Use the sample secret key for decryption
        let decrypted_data = ecdh_decrypt(
            &req.key,
            &get_unsecure_sample_secp256k1_sk(),
            &req.data,
            req.nonce,
        )
        .map_err(|e| RpcError::Custom(e.to_string()))?;

        Ok(IoDecryptionResponse { decrypted_data })
    }

    fn get_public_key(&self) -> Result<secp256k1::PublicKey, RpcError> {
        Ok(get_unsecure_sample_secp256k1_pk())
    }

    fn get_genesis_data(&self) -> Result<GenesisDataResponse, RpcError> {
        unimplemented!("genesis_get_data not implemented for mock server")
    }

    fn get_snapsync_backup(&self, _req: SnapSyncRequest) -> Result<SnapSyncResponse, RpcError> {
        unimplemented!("provide_snapsync_backup not implemented for mock server")
    }

    fn sign(&self, _req: Secp256k1SignRequest) -> Result<Secp256k1SignResponse, RpcError> {
        unimplemented!("secp256k1_sign not implemented for mock server")
    }

    fn verify(&self, _req: Secp256k1VerifyRequest) -> Result<Secp256k1VerifyResponse, RpcError> {
        unimplemented!("secp256k1_verify not implemented for mock server")
    }

    fn get_attestation_evidence(
        &self,
        _req: AttestationGetEvidenceRequest,
    ) -> Result<AttestationGetEvidenceResponse, RpcError> {
        unimplemented!("attestation_get_evidence not implemented for mock server")
    }

    fn eval_attestation_evidence(
        &self,
        _req: AttestationEvalEvidenceRequest,
    ) -> Result<AttestationEvalEvidenceResponse, RpcError> {
        unimplemented!("attestation_eval_evidence not implemented for mock server")
    }
}
