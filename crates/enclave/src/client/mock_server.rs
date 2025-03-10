use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use anyhow::Result;
use jsonrpsee::{
    core::{async_trait, RpcResult},
    server::ServerHandle,
    Methods,
};

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
    snapshot::{
        PrepareEncryptedSnapshotRequest, PrepareEncryptedSnapshotResponse,
        RestoreFromEncryptedSnapshotRequest, RestoreFromEncryptedSnapshotResponse,
    },
    snapsync::{SnapSyncRequest, SnapSyncResponse},
    tx_io::{IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse},
};

use super::{
    rpc::{BuildableServer, EnclaveApiServer},
    ENCLAVE_DEFAULT_ENDPOINT_ADDR, ENCLAVE_DEFAULT_ENDPOINT_PORT,
};

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
        Ok(get_unsecure_sample_secp256k1_pk())
    }

    async fn health_check(&self) -> RpcResult<String> {
        Ok("OK".to_string())
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
        // load key and encrypt data
        let encrypted_data = ecdh_encrypt(
            &request.key,
            &get_unsecure_sample_secp256k1_sk(),
            request.data,
            request.nonce,
        )
        .unwrap();

        Ok(IoEncryptionResponse { encrypted_data })
    }

    async fn decrypt(&self, request: IoDecryptionRequest) -> RpcResult<IoDecryptionResponse> {
        // load key and decrypt data
        let decrypted_data = ecdh_decrypt(
            &request.key,
            &get_unsecure_sample_secp256k1_sk(),
            request.data,
            request.nonce,
        )
        .map_err(|e| rpc_invalid_ciphertext_error(e))?;

        Ok(IoDecryptionResponse { decrypted_data })
    }

    async fn get_eph_rng_keypair(&self) -> RpcResult<schnorrkel::keys::Keypair> {
        Ok(get_unsecure_sample_schnorrkel_keypair())
    }

    async fn prepare_encrypted_snapshot(
        &self,
        _request: PrepareEncryptedSnapshotRequest,
    ) -> RpcResult<PrepareEncryptedSnapshotResponse> {
        unimplemented!("prepare_encrypted_snapshot not implemented for mock server")
    }

    async fn restore_from_encrypted_snapshot(
        &self,
        _request: RestoreFromEncryptedSnapshotRequest,
    ) -> RpcResult<RestoreFromEncryptedSnapshotResponse> {
        unimplemented!("restore_from_encrypted_snapshot not implemented for mock server")
    }
}
