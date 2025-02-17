use anyhow::Result;
use std::net::SocketAddr;

use seismic_enclave::client::http_client::{TEE_DEFAULT_ENDPOINT_ADDR, TEE_DEFAULT_ENDPOINT_PORT};
use seismic_enclave_server::server::start_rpc_server;

/// Initializes a server with the given address and handlers
#[tokio::main]
async fn main() -> Result<()> {
    let addr = SocketAddr::from((TEE_DEFAULT_ENDPOINT_ADDR, TEE_DEFAULT_ENDPOINT_PORT));
    start_rpc_server(addr).await?;
    Ok(())
}
