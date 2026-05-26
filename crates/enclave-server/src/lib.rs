mod attestation;
mod key_manager;
mod server;
pub mod utils;

const ENCLAVE_DEFAULT_ENDPOINT_IP: &str = "127.0.0.1";
pub const ENCLAVE_DEFAULT_ENDPOINT_PORT: u16 = 7878;
const ENCLAVE_DEFAULT_DATA_DIR: &str = "/var/lib/enclave";

use anyhow::Result;
use clap::Parser;
use seismic_enclave::mock::start_mock_server;
use std::{net::SocketAddr, path::PathBuf};
use tracing::info;

/// Command line arguments for the enclave server
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// The ip to bind the JSON-RPC server to.
    #[arg(long, default_value_t = ENCLAVE_DEFAULT_ENDPOINT_IP.to_string())]
    pub ip: String,

    /// The port to bind the server to
    #[arg(long, default_value_t = ENCLAVE_DEFAULT_ENDPOINT_PORT)]
    pub port: u16,

    /// Flag if this is the genesis node that needs to generate the keys
    #[arg(long, env = "SEISMIC_ENCLAVE_GENESIS_NODE", default_value_t = false)]
    pub genesis_node: bool,

    /// Comma-separated list of peer URLs to fetch root key from (e.g. `http://10.0.0.1:7878`).
    /// Required when `genesis_node` is false.
    #[arg(long, env = "SEISMIC_ENCLAVE_PEERS", value_delimiter = ',')]
    pub peers: Vec<String>,

    /// Directory for service-managed persistent state (currently just `root_key`).
    ///
    /// FHS-shaped default (`/var/lib/enclave`); production routes this onto a
    /// LUKS-encrypted mount via a `BindPaths=` entry in the systemd unit so the
    /// binary stays unaware of the underlying storage layout. Tests inject a
    /// `tempfile::tempdir()`; local dev can point at any writable path.
    #[arg(
        long,
        env = "SEISMIC_ENCLAVE_DATA_DIR",
        default_value = ENCLAVE_DEFAULT_DATA_DIR,
    )]
    pub data_dir: PathBuf,

    /// Run the dev-only mock server instead of the real enclave.
    ///
    /// When set, `Args::start` dispatches to
    /// `seismic_enclave::mock::start_mock_server` (in
    /// `crates/enclave/src/mock.rs`) which serves the same JSON-RPC
    /// surface but returns hardcoded test keys
    /// (`311d54d3bf8359c70827122a44a7b4458733adce3c51c6b59d9acfce85e07505`
    /// for tx_io_sk, zero-bytes for snapshot_key, etc.). Skips
    /// attestation and peer fetch. Used by `sanvil` / `sreth` local
    /// dev where TDX isn't available and clients know the dev pubkeys.
    ///
    /// **Never set this flag in a TDX deployment** — it disables every
    /// confidentiality property the chain depends on (anyone can
    /// decrypt any TxSeismic calldata, snapshots are unencrypted, RNG
    /// is predictable).
    #[arg(long, default_value_t = false)]
    pub mock: bool,
}

impl Args {
    pub async fn start(self) -> Result<()> {
        let addr: SocketAddr = format!("{}:{}", self.ip, self.port).parse()?;

        info!("Starting TDX Quote JSON-RPC Server on {addr}...");

        if self.mock {
            start_mock_server(addr).await
        } else {
            server::start_server(addr, self).await
        }
    }
}
