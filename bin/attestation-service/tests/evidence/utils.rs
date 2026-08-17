use alloy_primitives::B256;
use jsonrpsee::{RpcModule, server::ServerBuilder};
use seismic_attestation::NetworkManifestV1;
use seismic_attestation_service::Args;
use seismic_custodian_ipc::server::{MethodAcl, bind, serve};
use seismic_custodian_service::{dispatch::dispatch, state::CustodianState};
use std::path::{Path, PathBuf};

pub fn get_args(n: u16, peers: Vec<String>, custodian_socket: PathBuf, reth_rpc_url: &str) -> Args {
    let port = 7878 + n;
    Args {
        ip: "0.0.0.0".to_string(),
        port,
        peers,
        custodian_socket,
        reth_rpc_url: reth_rpc_url.parse().expect("valid mock registry URL"),
        max_policy_age: None,
    }
}

/// The genesis block the fixture manifest commits to, read from the fixture
/// itself so the stand-in chain and the manifest the service loads can never
/// disagree.
fn fixture_genesis_hash() -> B256 {
    const FIXTURE: &[u8] =
        include_bytes!("../../../../crates/network-manifest/fixtures/network-manifest-v1.json");
    B256::from(
        NetworkManifestV1::from_json_bytes(FIXTURE)
            .expect("fixture manifest is valid")
            .eth
            .genesis_hash,
    )
}

/// Serve a permissive stand-in for the node-local reth that answers the
/// responder's admission reads: `eth_getBlockByNumber` answers the `earliest`,
/// `latest` and `finalized` tag queries — and only those — with the manifest's
/// pinned genesis at block 0 (so the chain is the one `network_id` commits to)
/// and a fresh block past genesis for the other two (so the freshness gate
/// passes), and every `eth_call` returns ABI-encoded `true`, so the runner's
/// own measurements count as registry-accepted. These tests thereby exercise
/// the full live-TEE admission path — verified evidence → admission ID → fresh
/// chain state → registry query — while denial behavior is covered by the
/// admission module's unit tests.
pub async fn spawn_accepting_registry() -> String {
    let server = ServerBuilder::default()
        .build("127.0.0.1:0")
        .await
        .expect("bind mock registry endpoint");
    let addr = server.local_addr().expect("mock registry local addr");
    let mut module = RpcModule::new(());
    let genesis_hash = fixture_genesis_hash();
    module
        .register_method("eth_getBlockByNumber", move |params, _, _| {
            let (tag, _full_transactions): (String, bool) = params.parse()?;
            let mut block = alloy::rpc::types::Block::<alloy::rpc::types::Transaction>::default();
            match tag.as_str() {
                "earliest" => block.header.hash = genesis_hash,
                "latest" | "finalized" => {
                    block.header.inner.number = 1;
                    // Milliseconds, like real Seismic headers: the freshness
                    // gate reads the timestamp in that unit.
                    block.header.inner.timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("system clock after epoch")
                        .as_millis() as u64;
                }
                other => {
                    return Err(jsonrpsee::types::ErrorObjectOwned::owned(
                        -32000,
                        format!(
                            "mock reth serves only the earliest, latest and finalized tags, \
                             got {other}"
                        ),
                        None::<()>,
                    ));
                }
            }
            Ok(serde_json::to_value(block).expect("serialize mock block"))
        })
        .expect("register eth_getBlockByNumber");
    module
        .register_method("eth_call", |_, _, _| {
            const ABI_ENCODED_TRUE: &str =
                "0x0000000000000000000000000000000000000000000000000000000000000001";
            ABI_ENCODED_TRUE.to_string()
        })
        .expect("register eth_call");
    let handle = server.start(module);
    // The server stops when its handle drops; park the handle in a task that
    // outlives the test body.
    tokio::spawn(handle.stopped());
    format!("http://{addr}")
}

/// Serve `state` over a custodian socket from a dedicated thread — the same
/// transport and dispatch the standalone `seismic-custodian-service` binary runs.
pub fn spawn_custodian(state: CustodianState, socket: &Path) {
    let listener = bind(socket).expect("bind custodian socket");
    std::thread::spawn(move || {
        serve(listener, MethodAcl::own_uid_only(), move |request| {
            dispatch(&state, request)
        })
    });
}
