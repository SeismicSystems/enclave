mod admission;
pub mod api;
pub mod bootstrap;
mod luks_status;
mod network;
pub mod rpc_error;
mod server;
pub mod utils;

/// Loopback as a safe default but production should listen on `0.0.0.0` instead:
/// joining peers fetch the wrapped root key from here and deploy tooling polls node status.
const DEFAULT_ENDPOINT_IP: &str = "127.0.0.1";
const DEFAULT_ENDPOINT_PORT: u16 = 7878;
/// The node's own reth, assumed to serve HTTP JSON-RPC on the conventional
/// loopback endpoint.
const DEFAULT_RETH_RPC_URL: &str = "http://127.0.0.1:8545";

use anyhow::Result;
use clap::Parser;
use seismic_custodian_ipc::DEFAULT_CUSTODIAN_SOCKET_PATH;
use std::{net::SocketAddr, path::PathBuf};
use tracing::info;

/// Command line arguments for the attestation service
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// The ip to bind the JSON-RPC server to.
    #[arg(long, default_value_t = DEFAULT_ENDPOINT_IP.to_string())]
    pub ip: String,

    /// The port to bind the server to
    #[arg(long, default_value_t = DEFAULT_ENDPOINT_PORT)]
    pub port: u16,

    /// Filesystem path for the custodian IPC socket.
    #[arg(long, default_value = DEFAULT_CUSTODIAN_SOCKET_PATH)]
    pub custodian_socket: PathBuf,

    /// Comma-separated list of peer URLs (e.g. `http://10.0.0.1:7878`) to
    /// fetch the root key from when the local custodian starts without one.
    /// Required on every node whose custodian does not run with
    /// `--genesis-node`: with a keyless custodian and no peers there is no
    /// way to obtain the root key, so startup fails immediately.
    #[arg(long, env = "SEISMIC_ROOT_KEY_PEERS", value_delimiter = ',')]
    pub peers: Vec<String>,

    /// HTTP JSON-RPC endpoint of this node's own reth, queried to check each
    /// joining peer's admission ID against the on-chain MeasurementRegistry.
    /// An unreachable endpoint denies joins (fail closed) — it never blocks
    /// this service's startup or its other RPCs.
    #[arg(long, env = "SEISMIC_RETH_RPC_URL", default_value = DEFAULT_RETH_RPC_URL)]
    pub reth_rpc_url: url::Url,

    /// Bound on the finalized-block age admission decisions accept; `None`
    /// keeps the production default. Deliberately not a CLI flag: only the
    /// admission integration suite tightens it, to observe the staleness
    /// denial without waiting out the production bound.
    #[arg(skip)]
    pub max_policy_age: Option<std::time::Duration>,
}

impl Args {
    pub async fn start(self) -> Result<()> {
        // Quote verification's collateral fetching (attested-tls) builds
        // rustls-backed HTTP clients, which need a process-level crypto
        // provider that only the application can choose. Install it before
        // anything verifies evidence; a provider installed even earlier by
        // an embedding process wins, and any provider serves.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let addr: SocketAddr = format!("{}:{}", self.ip, self.port).parse()?;

        info!("Starting attestation-service JSON-RPC server on {addr}...");

        server::start_server(addr, self).await
    }
}
