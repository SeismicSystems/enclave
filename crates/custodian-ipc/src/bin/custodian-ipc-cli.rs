//! Debug client for the custodian socket — the `socat` stand-in for a binary
//! wire format, and the reference consumer of [`CustodianClient`].
//!
//! Prints public material and SHA-256 fingerprints only, never raw secrets:
//! good enough to check "is the custodian up and deriving the keys every
//! other node derives" without turning a debug tool into a key-exfil path.

use anyhow::Result;
use clap::{Parser, Subcommand};
use seismic_custodian_ipc::{CustodianClient, DEFAULT_CUSTODIAN_SOCKET_PATH};
use sha2::{Digest as _, Sha256};

#[derive(Parser)]
#[command(about = "Debug client for the Seismic key-custodian Unix socket")]
struct Cli {
    /// Path to the custodian socket.
    #[arg(long, default_value = DEFAULT_CUSTODIAN_SOCKET_PATH)]
    socket: std::path::PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Liveness probe.
    Ping,
    /// Fetch every purpose key this UID is allowed; prints the tx_io public
    /// key, SHA-256 fingerprints of the secret material, and per-purpose
    /// denials.
    PurposeKeys {
        #[arg(long, default_value_t = 0)]
        epoch: u64,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut client = CustodianClient::connect(&cli.socket).await?;
    match cli.command {
        Command::Ping => {
            client.ping().await?;
            println!("OK");
        }
        Command::PurposeKeys { epoch } => {
            println!("epoch:               {epoch}");
            match client.get_tx_io_keypair(epoch).await {
                Ok(keys) => {
                    println!("tx_io pk:            {}", hex::encode(keys.pk));
                    println!("tx_io sk sha256:     {}", fingerprint(&keys.sk));
                }
                Err(e) => println!("tx_io:               {e}"),
            }
            match client.get_rng_keypair(epoch).await {
                Ok(keys) => {
                    println!("rng_keypair sha256:  {}", fingerprint(&keys.keypair));
                }
                Err(e) => println!("rng_keypair:         {e}"),
            }
            match client.get_snapshot_key(epoch).await {
                Ok(key) => {
                    println!("snapshot_key sha256: {}", fingerprint(&key.key));
                }
                Err(e) => println!("snapshot_key:        {e}"),
            }
        }
    }
    Ok(())
}

fn fingerprint(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
