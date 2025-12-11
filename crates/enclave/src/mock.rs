/* Mock enclave server for testing and running on non-tdx machines */

use std::net::SocketAddr;

use jsonrpsee::core::{RpcResult, async_trait};
use jsonrpsee::server::ServerBuilder;

use crate::api::{
    AttestationGetEvidenceResponse, GetPurposeKeysResponse, ShareRootKeyResponse, TdxQuoteRpcServer,
};
use crate::{
    get_unsecure_sample_schnorrkel_keypair, get_unsecure_sample_secp256k1_pk,
    get_unsecure_sample_secp256k1_sk,
};

pub struct MockServer {}

pub async fn start_mock_server(addr: SocketAddr) -> anyhow::Result<()> {
    let server = ServerBuilder::default().build(addr).await?;

    let handle = server.start(MockServer {}.into_rpc());

    println!("TDX Quote JSON-RPC Server started at {}", addr);

    handle.stopped().await;
    Ok(())
}

#[async_trait]
impl TdxQuoteRpcServer for MockServer {
    async fn health_check(&self) -> RpcResult<String> {
        Ok("OK".to_string())
    }

    async fn get_purpose_keys(&self, _epoch: u64) -> RpcResult<GetPurposeKeysResponse> {
        Ok(GetPurposeKeysResponse {
            tx_io_sk: get_unsecure_sample_secp256k1_sk(),
            tx_io_pk: get_unsecure_sample_secp256k1_pk(),
            snapshot_key_bytes: [0u8; 32],
            rng_keypair: get_unsecure_sample_schnorrkel_keypair(),
        })
    }

    async fn get_attestation_evidence(&self) -> RpcResult<AttestationGetEvidenceResponse> {
        unimplemented!("get_attestation_evidence not implemented for mock server")
    }

    async fn eval_attestation_evidence(
        &self,
        _hcl_report: Vec<u8>,
        _quote: Vec<u8>,
    ) -> RpcResult<()> {
        unimplemented!("eval_attestation_evidence not implemented for mock server")
    }

    async fn boot_share_root_key(&self, _quote: Vec<u8>) -> RpcResult<ShareRootKeyResponse> {
        Ok(ShareRootKeyResponse {
            root_key: *get_unsecure_sample_secp256k1_sk().as_ref(),
        })
    }

    async fn download_encrypted_snapshot(&self, _epoch: u64, _url: String) -> RpcResult<()> {
        unimplemented!("prepare_encrypted_snapshot is not implemented for mock server")
    }

    async fn restore_from_encrypted_snapshot(&self, _epoch: u64) -> RpcResult<()> {
        unimplemented!("restore_encrypted_snapshot is not implemented for mock server")
    }
}
