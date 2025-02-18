use anyhow::Result;
use std::net::SocketAddr;
use tracing::info;

use seismic_enclave_server::server::{
    init_tracing, start_rpc_server, TEE_DEFAULT_ENDPOINT_ADDR, TEE_DEFAULT_ENDPOINT_PORT,
};

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
