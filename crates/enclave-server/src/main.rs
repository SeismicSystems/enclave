use anyhow::Result;
use tracing::info;

use seismic_enclave_server::server::{init_tracing, start_rpc_server, EnclaveServer};

/// Initializes a server with the given address and handlers
#[tokio::main]
async fn main() -> Result<()> {
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    init_tracing();

    info!("Enclave server starting");

    let handle = start_rpc_server(EnclaveServer::default()).await?;
    handle.stopped().await;

    Ok(())
}
