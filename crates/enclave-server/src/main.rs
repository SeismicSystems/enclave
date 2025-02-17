use anyhow::Result;
use std::net::SocketAddr;
use tracing::info;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use seismic_enclave::client::http_client::{TEE_DEFAULT_ENDPOINT_ADDR, TEE_DEFAULT_ENDPOINT_PORT};
use seismic_enclave_server::server::start_rpc_server;

/// Initializes a server with the given address and handlers
#[tokio::main]
async fn main() -> Result<()> {
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    init_tracing();

    info!("Enclave server starting");

    let addr = SocketAddr::from((TEE_DEFAULT_ENDPOINT_ADDR, TEE_DEFAULT_ENDPOINT_PORT));
    start_rpc_server(addr).await?;
    Ok(())
}

fn init_tracing() {
    // Read log level from RUST_LOG
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));

    // Initialize the subscriber
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter) // Use dynamic log level
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    info!("Enclave server tracing initialized");
}
