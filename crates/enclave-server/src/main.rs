mod api;
mod attestation;
mod req_res;
mod server;
pub mod utils;
use std::net::SocketAddr;
pub mod key_manager;

use clap::Parser;
use tracing::info;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

const ENCLAVE_DEFAULT_ENDPOINT_IP: &str = "0.0.0.0";
pub const ENCLAVE_DEFAULT_ENDPOINT_PORT: u16 = 7878;

/// Command line arguments for the enclave server
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The ip to bind the server to
    #[arg(long, default_value_t = ENCLAVE_DEFAULT_ENDPOINT_IP.to_string())]
    ip: String,

    /// The port to bind the server to
    #[arg(long, default_value_t = ENCLAVE_DEFAULT_ENDPOINT_PORT)]
    port: u16,

    /// Flag if this is the genesis node that needs to generate the keys
    #[arg(long, default_value_t = false)]
    genesis_node: bool,

    /// List of peer ips to fetch root key from. Must be {ip}:{port}
    #[arg(long)]
    peers: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let args = Args::parse();
    let addr: SocketAddr = format!("{}:{}", args.ip, args.port).parse()?;

    println!("Starting TDX Quote JSON-RPC Server on {addr}...");
    server::start_server(addr, args.genesis_node, args.peers).await
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
