use clap::{Parser, Subcommand};
use error::Result;
use tracing::{error, info};

mod config;
mod disk;
mod error;
mod luks;
mod server;
mod persistence;
mod ssh;

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
        std::env::set_var(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin",
        );
    }

    let args = Args::parse();

    let device_path = disk::discover_persistent_disk_with_retry().await?;
    info!("Found persistent disk device: {}", device_path.display());

    match args.command {
        Command::WaitForKey => luks::wait_for_key(device_path).await,
        Command::SetPassphrase => luks::set_passphrase(device_path).await,
    }
}
