use anyhow::{Context, Result};
use std::env;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use log::{warn, debug};
use attestation_agent::AttestationAgent;
use attestation_agent::AttestationAPIs;


#[tokio::main]
async fn main() -> Result<()> {
    // Initialize the logger
    env_logger::init();

    // Proper error handling
    let aa = AttestationAgent::new(None)
        .context("Failed to create an AttestationAgent")?;
    debug!("Detected TEE type: {:?}", aa.get_tee_type());

    Ok(())
}
