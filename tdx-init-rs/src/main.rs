use clap::{Parser, Subcommand};
use error::Result;
use tracing::info;

mod config;
mod disk;
mod error;
mod keys;
mod luks;
mod passphrase;
mod persistence;
mod server;
mod ssh;
mod utils;

const SYSTEM_PATH: &str = "/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin";

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    // Wait for the key to be provided via HTTP or extract from existing LUKS header
    WaitForKey,
    // Set up the encrypted disk with a passphrases
    SetPassphrase,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    unsafe {
        std::env::set_var("PATH", SYSTEM_PATH);
    }

    let args = Args::parse();

    let device_path = disk::discover_persistent_disk_with_retry().await?;
    info!("Found persistent disk device: {}", device_path.display());

    match args.command {
        Command::WaitForKey => keys::wait_for_key(device_path).await,
        Command::SetPassphrase => passphrase::set_passphrase(device_path).await,
    }
}
