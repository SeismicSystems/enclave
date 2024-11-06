use anyhow::Result;
use std::net::SocketAddr;

use tee_service::server::start_server;
use tee_service_api::client::http_client::{TEE_DEFAULT_ENDPOINT_ADDR, TEE_DEFAULT_ENDPOINT_PORT};

/// Initializes a server with the given address and handlers
#[tokio::main]
async fn main() -> Result<()> {
    let addr = SocketAddr::from((TEE_DEFAULT_ENDPOINT_ADDR, TEE_DEFAULT_ENDPOINT_PORT));
    start_server(addr).await?;
    Ok(())
}
