pub mod api;
mod bootstrap;
mod luks_status;
mod network;
mod server;
pub mod utils;

/// Loopback as a safe default but production should listen on `0.0.0.0` instead:
/// joining peers fetch the wrapped root key from here and deploy tooling polls node status.
const DEFAULT_ENDPOINT_IP: &str = "127.0.0.1";
const DEFAULT_ENDPOINT_PORT: u16 = 7878;

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
}

impl Args {
    pub async fn start(self) -> Result<()> {
        let addr: SocketAddr = format!("{}:{}", self.ip, self.port).parse()?;

        info!("Starting attestation-service JSON-RPC server on {addr}...");

        server::start_server(addr, self).await
    }
}
