use clap::{Parser, Subcommand};
use error::Result;

mod config;
mod error;
mod keys;
mod persistence;
mod server;
mod utils;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Wait for an InitConfig POST and write it to /persistent/conf/node.json.
    /// Exits immediately if the config file already exists (subsequent boots).
    WaitForConfig,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    match args.command {
        Command::WaitForConfig => keys::wait_for_config().await,
    }
}
