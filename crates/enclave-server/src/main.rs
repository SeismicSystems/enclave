use anyhow::Result;
use seismic_enclave::client::{ENCLAVE_DEFAULT_ENDPOINT_ADDR, ENCLAVE_DEFAULT_ENDPOINT_PORT};
use std::net::SocketAddr;
use tracing::info;

use seismic_enclave_server::server::start_rpc_server;

/// Initializes a server with the given address and handlers
#[tokio::main]
async fn main() -> Result<()> {
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    info!("Enclave server starting");

    let addr = SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_ADDR, ENCLAVE_DEFAULT_ENDPOINT_PORT));
    let handle = start_rpc_server(addr).await?;
    handle.stopped().await;

    Ok(())
}
