use anyhow::Result;
use std::net::SocketAddr;

use tee_service::server::start_server;

/// Initializes a server with the given address and handlers
#[tokio::main]
async fn main() -> Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 7878));
    start_server(addr).await?;
    Ok(())
}


