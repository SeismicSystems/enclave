use clap::arg;
use clap::Parser;
use seismic_enclave::client::rpc::BuildableServer;
use seismic_enclave::{ENCLAVE_DEFAULT_ENDPOINT_IP, ENCLAVE_DEFAULT_ENDPOINT_PORT};
use seismic_enclave_server::key_manager::KeyManager;
use seismic_enclave_server::key_manager::NetworkKeyProvider;
use seismic_enclave_server::server::{init_tracing, EnclaveServer, EnclaveServerBuilder};
use std::net::IpAddr;
use tracing::info;

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
    let builder: EnclaveServerBuilder<KeyManager> = EnclaveServer::<KeyManager>::builder()
        .with_ip(args.ip)
        .with_port(args.port)
        // TODO: load from env / set this in yocto builder
        .with_key_provider(KeyManager::new([0u8; 32]));

    let server: EnclaveServer<KeyManager> = builder.build().await.unwrap();
    let handle = server.start().await.unwrap();

    handle.stopped().await;
}
