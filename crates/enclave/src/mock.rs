/* Mock enclave server for testing and running on non-tdx machines */

use std::net::SocketAddr;

use jsonrpsee::core::{RpcResult, async_trait};
use jsonrpsee::server::ServerBuilder;
use tracing::info;

use crate::api::{GetPurposeKeysResponse, LuksProvisioningStatus, TdxQuoteRpcServer};
use crate::{
    get_unsecure_sample_schnorrkel_keypair, get_unsecure_sample_secp256k1_pk,
    get_unsecure_sample_secp256k1_sk,
};

pub struct MockServer {}

pub async fn start_mock_server(addr: SocketAddr) -> anyhow::Result<()> {
    let server = ServerBuilder::default().build(addr).await?;

    let handle = server.start(MockServer {}.into_rpc());

    info!("TDX Quote JSON-RPC Server started at {}", addr);

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

    async fn get_luks_provisioning_status(&self) -> RpcResult<LuksProvisioningStatus> {
        // The mock has no real persistent disk, so nothing is ever provisioning.
        Ok(LuksProvisioningStatus::Idle)
    }
}
