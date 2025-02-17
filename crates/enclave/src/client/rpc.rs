// JSON-RPC Trait for Server and Client
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;

use crate::coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse};
use crate::coco_as::{AttestationEvalEvidenceRequest, AttestationEvalEvidenceResponse};
use crate::genesis::GenesisDataResponse;
use crate::signing::{
    Secp256k1SignRequest, Secp256k1SignResponse, Secp256k1VerifyRequest, Secp256k1VerifyResponse,
};
use crate::snapsync::{SnapSyncRequest, SnapSyncResponse};
use crate::tx_io::{
    IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse,
};

#[rpc(client, server)]
pub trait EnclaveApi: TxIoApi + SigningApi + AttestationApi {
    // Health Check
    #[method(name = "health.check")]
    async fn health_check(&self) -> RpcResult<String>;

    // Genesis
    #[method(name = "genesis.get_data")]
    async fn genesis_get_data(&self) -> RpcResult<GenesisDataResponse>;

    // SnapSync
    #[method(name = "snapsync.provide_backup")]
    async fn provide_snapsync_backup(
        &self,
        request: SnapSyncRequest,
    ) -> RpcResult<SnapSyncResponse>;
}

#[rpc(client, server)]
pub trait SigningApi {
    #[method(name = "signing.sign")]
    async fn secp256k1_sign(&self, req: Secp256k1SignRequest) -> RpcResult<Secp256k1SignResponse>;

    #[method(name = "signing.verify")]
    async fn secp256k1_verify(
        &self,
        req: Secp256k1VerifyRequest,
    ) -> RpcResult<Secp256k1VerifyResponse>;
}

#[rpc(client, server)]
pub trait AttestationApi {
    // Attestation
    #[method(name = "attestation.aa.get_evidence")]
    async fn attestation_get_evidence(
        &self,
        req: AttestationGetEvidenceRequest,
    ) -> RpcResult<AttestationGetEvidenceResponse>;

    #[method(name = "attestation.as.eval_evidence")]
    async fn attestation_eval_evidence(
        &self,
        req: AttestationEvalEvidenceRequest,
    ) -> RpcResult<AttestationEvalEvidenceResponse>;
}

#[rpc(client, server)]
pub trait TxIoApi {
    // Transaction I/O
    #[method(name = "tx_io.encrypt")]
    async fn tx_io_encrypt(&self, req: IoEncryptionRequest) -> RpcResult<IoEncryptionResponse>;

    #[method(name = "tx_io.decrypt")]
    async fn tx_io_decrypt(&self, req: IoDecryptionRequest) -> RpcResult<IoDecryptionResponse>;
}
