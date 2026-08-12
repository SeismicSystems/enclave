use jsonrpsee::{RpcModule, server::ServerBuilder};
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

/// Serve a permissive stand-in for the node-local reth that answers the
/// responder's admission reads: `eth_getBlockByNumber` answers the `latest`
/// and `finalized` tag queries — and only those — with a fresh block past
/// genesis (so the freshness gate passes), and every `eth_call` returns
/// ABI-encoded `true`, so the runner's own measurements count as
/// registry-accepted. These tests thereby exercise the full live-TEE
/// admission path — verified evidence → admission ID → fresh chain state →
/// registry query — while denial behavior is covered by the admission
/// module's unit tests.
pub async fn spawn_accepting_registry() -> String {
    let server = ServerBuilder::default()
        .build("127.0.0.1:0")
        .await
        .expect("bind mock registry endpoint");
    let addr = server.local_addr().expect("mock registry local addr");
    let mut module = RpcModule::new(());
    module
        .register_method("eth_getBlockByNumber", |params, _, _| {
            let (tag, _full_transactions): (String, bool) = params.parse()?;
            if tag != "latest" && tag != "finalized" {
                return Err(jsonrpsee::types::ErrorObjectOwned::owned(
                    -32000,
                    format!("mock reth serves only the latest and finalized tags, got {tag}"),
                    None::<()>,
                ));
            }
            let mut block = alloy::rpc::types::Block::<alloy::rpc::types::Transaction>::default();
            block.header.inner.number = 1;
            // Milliseconds, like real Seismic headers: the freshness gate
            // reads the timestamp in that unit.
            block.header.inner.timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after epoch")
                .as_millis() as u64;
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
