use clap::Parser;
use seismic_attestation_service::{Args, utils::init_tracing};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    Args::parse().start().await
}
