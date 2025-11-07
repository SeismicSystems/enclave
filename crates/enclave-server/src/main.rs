use clap::Parser;
use seismic_enclave_server::Args;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Args::parse().start().await
}
