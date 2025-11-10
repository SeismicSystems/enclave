/* Mock enclave server for testing and running on non-tdx machines */

use std::net::SocketAddr;
use std::str::FromStr as _;

use jsonrpsee::core::{RpcResult, async_trait};
use jsonrpsee::server::ServerBuilder;
use schnorrkel::keys::Keypair as SchnorrkelKeypair;
use schnorrkel::{ExpansionMode, MiniSecretKey};

use crate::{
    api::TdxQuoteRpcServer,
    req_res::{AttestationGetEvidenceResponse, GetPurposeKeysResponse, ShareRootKeyResponse},
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

    async fn prepare_encrypted_snapshot(&self) -> RpcResult<()> {
        unimplemented!("prepare_encrypted_snapshot is not implemented for mock server")
    }

    async fn restore_from_encrypted_snapshot(&self) -> RpcResult<()> {
        unimplemented!("restore_encrypted_snapshot is not implemented for mock server")
    }
}

pub fn get_unsecure_sample_secp256k1_sk() -> secp256k1::SecretKey {
    secp256k1::SecretKey::from_str(
        "311d54d3bf8359c70827122a44a7b4458733adce3c51c6b59d9acfce85e07505",
    )
    .unwrap()
}

/// Returns a sample Secp256k1 public key for testing purposes.
pub fn get_unsecure_sample_secp256k1_pk() -> secp256k1::PublicKey {
    secp256k1::PublicKey::from_str(
        "028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0",
    )
    .unwrap()
}

/// Returns a sample SchnorrkelKeypair public key for testing purposes.
pub fn get_unsecure_sample_schnorrkel_keypair() -> SchnorrkelKeypair {
    let mini_secret_key = MiniSecretKey::from_bytes(&[
        221, 143, 4, 149, 139, 56, 101, 208, 232, 50, 47, 39, 112, 211, 4, 111, 63, 63, 202, 141,
        138, 195, 190, 41, 139, 177, 214, 90, 176, 210, 173, 14,
    ])
    .unwrap();
    mini_secret_key.expand(ExpansionMode::Uniform).into()
}
