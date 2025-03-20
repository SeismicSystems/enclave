use clap::arg;
use clap::Parser;
use std::net::IpAddr;
use tracing::info;

use seismic_enclave::client::rpc::BuildableServer;
use seismic_enclave::{ENCLAVE_DEFAULT_ENDPOINT_ADDR, ENCLAVE_DEFAULT_ENDPOINT_PORT};
use seismic_enclave_server::server::{init_tracing, EnclaveServer};

/// Command line arguments for the enclave server
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The address to bind the server to
    #[arg(long, default_value_t = ENCLAVE_DEFAULT_ENDPOINT_ADDR)]
    addr: IpAddr,

    /// The port to bind the server to
    #[arg(long, default_value_t = ENCLAVE_DEFAULT_ENDPOINT_PORT)]
    port: u16,
}

/// Initializes a server with the given address and handlers
#[tokio::main]
async fn main() {
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    init_tracing();

    let args = Args::parse();
    info!("Enclave server starting on {}:{}", args.addr, args.port);

    let handle = EnclaveServer::default()
        .with_addr(&args.addr.to_string())
        .with_port(args.port)
        .start()
        .await
        .unwrap();

    handle.stopped().await;
}
