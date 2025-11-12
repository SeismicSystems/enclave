use clap::Parser;
use seismic_enclave_server::{Args, utils::init_tracing};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    Args::parse().start().await
}
