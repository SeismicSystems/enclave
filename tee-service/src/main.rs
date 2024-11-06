use anyhow::Result;
use std::net::SocketAddr;

use tee_service::server::start_server;

/// Initializes a server with the given address and handlers
#[tokio::main]
async fn main() -> Result<()> {
    // 0.0.0.0 exposes to public internet
    // 127.0.0.1 will only allow other processes on machine to ping
    let addr = SocketAddr::from(([0, 0, 0, 0], 7878));
    // let addr = SocketAddr::from(([127, 0, 0, 1], 7878));
    start_server(addr).await?;
    Ok(())
}
