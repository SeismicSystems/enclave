//! Ops helper for observer custodian keys.
//!
//! Prints the public identities a summit keystore produces so operators can
//! confirm a parent and an observer hold the same `node_key.pem` — and which
//! child pubkey the parent will expect for a given chain id and index —
//! without touching a running service.
//!
//! Build: `cargo build --release -p seismic-observer-key --features cli`

use clap::{Parser, Subcommand};
use seismic_observer_key::{
    ObserverSigner, load_node_seed, master_public_from_seed, observer_namespace_from_chain_id,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "observer-keytool",
    about = "Inspect summit observer key identities"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the master node public key for a keystore.
    MasterPub {
        /// Summit keystore directory containing node_key.pem.
        #[arg(long, env = "SEISMIC_SUMMIT_KEY_DIR")]
        summit_key_dir: PathBuf,
    },
    /// Print the derived observer child public key for a chain id and index.
    ChildPub {
        /// Summit keystore directory containing node_key.pem.
        #[arg(long, env = "SEISMIC_SUMMIT_KEY_DIR")]
        summit_key_dir: PathBuf,
        /// EVM chain id the custodian deployment runs under.
        #[arg(long, env = "SEISMIC_CHAIN_ID")]
        chain_id: u64,
        /// Observer derivation index.
        #[arg(long)]
        index: u32,
    },
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::MasterPub { summit_key_dir } => {
            let seed = load_node_seed(&summit_key_dir)?;
            println!("{}", hex::encode(master_public_from_seed(&seed)));
        }
        Command::ChildPub {
            summit_key_dir,
            chain_id,
            index,
        } => {
            let seed = load_node_seed(&summit_key_dir)?;
            let namespace = observer_namespace_from_chain_id(chain_id);
            let signer = ObserverSigner::derive(&seed, &namespace, index);
            println!("{}", hex::encode(signer.public_key()));
        }
    }
    Ok(())
}
