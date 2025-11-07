// #![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
// #![cfg_attr(not(test), warn(unused_crate_dependencies))]

// pub mod attestation;
// pub mod key_manager;
// pub mod server;
// pub mod snapshot;
// pub mod utils;
pub mod api;
mod attestation;
mod key_manager;
mod req_res;
mod server;
pub mod utils;

// use clap as _; // used by main.rs

const ENCLAVE_DEFAULT_ENDPOINT_IP: &str = "0.0.0.0";
const DEFAULT_RETH_RPC: &str = "0.0.0.0:8545";
pub const ENCLAVE_DEFAULT_ENDPOINT_PORT: u16 = 7878;

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use tracing::info;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

/// Command line arguments for the enclave server
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// The ip to bind the server to
    #[arg(long, default_value_t = ENCLAVE_DEFAULT_ENDPOINT_IP.to_string())]
    pub ip: String,

    /// The port to bind the server to
    #[arg(long, default_value_t = ENCLAVE_DEFAULT_ENDPOINT_PORT)]
    pub port: u16,

    /// Flag if this is the genesis node that needs to generate the keys
    #[arg(long, default_value_t = false)]
    pub genesis_node: bool,

    /// List of peer ips to fetch root key from. Must be {ip}:{port}
    #[arg(long)]
    pub peers: Vec<String>,

    #[arg(long, default_value_t =DEFAULT_RETH_RPC.to_string())]
    pub reth_rpc_url: String,
}

impl Args {
    pub async fn start(self) -> Result<()> {
        init_tracing();

        let addr: SocketAddr = format!("{}:{}", self.ip, self.port).parse()?;

        println!("Starting TDX Quote JSON-RPC Server on {addr}...");
        server::start_server(addr, self.genesis_node, self.peers).await
    }
}

pub fn init_tracing() {
    // Read log level from RUST_LOG
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));

    // Initialize the subscriber
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter) // Use dynamic log level
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    info!("Enclave server tracing initialized");
}
