pub mod api;
mod attestation;
mod key_manager;
pub mod mock;
mod req_res;
mod server;
pub mod utils;
pub use req_res::*;

const ENCLAVE_DEFAULT_ENDPOINT_IP: &str = "0.0.0.0";
const DEFAULT_RETH_RPC: &str = "0.0.0.0:8545";
pub const ENCLAVE_DEFAULT_ENDPOINT_PORT: u16 = 7878;

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;

use crate::mock::start_mock_server;

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

    #[arg(long, default_value_t = false)]
    pub mock: bool,
}

impl Args {
    pub async fn start(self) -> Result<()> {
        let addr: SocketAddr = format!("{}:{}", self.ip, self.port).parse()?;

        println!("Starting TDX Quote JSON-RPC Server on {addr}...");

        if self.mock {
            start_mock_server(addr).await
        } else {
            server::start_server(addr, self.genesis_node, self.peers).await
        }
    }
}
