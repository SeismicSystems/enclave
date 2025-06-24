#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod attestation;
pub mod key_manager;
pub mod server;
pub mod utils;

use attestation_service::token::simple::SimpleAttestationTokenBroker;
use clap::arg;
use clap::Parser;
use std::net::IpAddr;
use time as _;
use tracing::info; // see Cargo.toml for explanation

use crate::key_manager::KeyManager;
use crate::server::{init_tracing, EnclaveServer, EnclaveServerBuilder};
use seismic_enclave::client::rpc::BuildableServer;
use seismic_enclave::{ENCLAVE_DEFAULT_ENDPOINT_IP, ENCLAVE_DEFAULT_ENDPOINT_PORT};

/// Command line arguments for the enclave server
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The ip to bind the server to
    #[arg(long, default_value_t = ENCLAVE_DEFAULT_ENDPOINT_IP)]
    ip: IpAddr,

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
    info!("Enclave server starting on {}:{}", args.ip, args.port);

    // Use type parameter for the key provider (e.g., DefaultKeyProvider)
    let builder: EnclaveServerBuilder<KeyManager> =
        EnclaveServer::<KeyManager, SimpleAttestationTokenBroker>::builder()
            .with_ip(args.ip)
            .with_port(args.port);

    let server: EnclaveServer<KeyManager, SimpleAttestationTokenBroker> =
        builder.build().await.unwrap();
    let handle = server.start().await.unwrap();

    handle.stopped().await;
}
