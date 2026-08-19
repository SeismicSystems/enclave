//! `seismic-centralized-custodian-service` — the standalone custodian for
//! the centralized phase, before the network moves to decentralized custody
//! inside TEEs.
//!
//! Serves the same Unix-socket API as `seismic-custodian-service` for
//! epoch 0, but epochs >= 1 arrive as signed, encrypted deliveries from a
//! security council over a TCP port instead of being derived. Runs with no
//! other Seismic binaries: the root key persists in a local keyfile (no
//! attested bootstrap, no LUKS handoff), and the delivery store is a plain
//! directory scanned at startup.
//!
//! The port speaks only the small framed council protocol (64 KiB frame
//! cap, capped connections, I/O timeouts), every delivery is
//! signature-checked before any state or disk is touched, and reachability
//! should be confined by the deployment's firewall.

use anyhow::{Context as _, Result, anyhow};
use clap::Parser;
use seismic_centralized_custodian_service::state::CentralizedCustodianState;
use seismic_centralized_custodian_service::{council, dispatch, root_key_file};
use seismic_council_delivery::network_id_from_chain_id;
use seismic_custodian::Custodian;
use seismic_custodian_ipc::DEFAULT_CUSTODIAN_SOCKET_PATH;
use seismic_custodian_ipc::server::{bind, serve};
use seismic_custodian_service::acl;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Default council listen address. 7878 is the attestation service.
const DEFAULT_COUNCIL_LISTEN_ADDR: &str = "0.0.0.0:7876";
/// Default state directory: the root keyfile and delivery envelopes live
/// here. The operator backs this up; nothing in it is plaintext except the
/// root key itself.
const DEFAULT_ROOT_KEY_PATH: &str = "/var/lib/seismic/custodian/root.key";
const DEFAULT_DELIVERY_DIR: &str = "/var/lib/seismic/custodian/deliveries";

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Filesystem path for the custodian IPC socket.
    #[arg(long, default_value = DEFAULT_CUSTODIAN_SOCKET_PATH)]
    socket: PathBuf,

    /// Path of the 32-byte root keyfile. If absent, the PUBLICLY KNOWN
    /// shared default is pinned there so every node agrees on epoch-0 keys
    /// with no coordination — epoch 0 then provides no confidentiality;
    /// rotate via the council immediately. Pre-place 32 random bytes for a
    /// secret root key instead.
    #[arg(long, env = "SEISMIC_ROOT_KEY_FILE", default_value = DEFAULT_ROOT_KEY_PATH)]
    root_key_file: PathBuf,

    /// Grant a local user access to key purposes over the socket, as
    /// USER:PURPOSE[,PURPOSE...]. Repeatable. Same grammar as
    /// seismic-custodian-service.
    #[arg(long, value_name = "USER:PURPOSES")]
    allow: Vec<String>,

    /// TCP address the council delivery port binds.
    #[arg(long, env = "SEISMIC_COUNCIL_LISTEN_ADDR", default_value = DEFAULT_COUNCIL_LISTEN_ADDR)]
    council_listen: SocketAddr,

    /// The security council's Ethereum address (0x + 40 hex chars). Every
    /// delivery envelope must carry an EIP-712 signature that recovers to
    /// it.
    #[arg(long, env = "SEISMIC_COUNCIL_ADDRESS", value_parser = parse_council_address)]
    council_address: CouncilAddress,

    /// The EVM chain id this custodian serves. Derives the network
    /// identifier that scopes every council signature and ciphertext, so
    /// the council tool must be run with the same value.
    #[arg(long, env = "SEISMIC_CHAIN_ID")]
    chain_id: u64,

    /// Directory where delivery envelopes persist. Envelopes contain the
    /// plaintext purpose keys (council-signed), so this directory is itself
    /// secret: protect it like the root keyfile.
    #[arg(long, default_value = DEFAULT_DELIVERY_DIR)]
    delivery_dir: PathBuf,
}

fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    // Everything that can be misconfigured fails here, before the sockets
    // exist: ACL grants, the delivery store, the keyfile.
    let method_acl = acl::method_acl_from_allow_specs(&args.allow)
        .context("resolving --allow grants (is the user missing?)")?;
    let network_id = network_id_from_chain_id(args.chain_id);
    info!(
        chain_id = args.chain_id,
        %network_id,
        "delivery envelopes must be bound to this network"
    );

    let root_key = root_key_file::load_or_default(&args.root_key_file)?;
    let state = Arc::new(
        CentralizedCustodianState::new(
            Custodian::new(root_key),
            args.delivery_dir,
            args.council_address.0,
            network_id,
        )
        .context("loading the delivery store")?,
    );

    let unix_listener = bind(&args.socket)
        .with_context(|| format!("binding custodian socket {}", args.socket.display()))?;
    let tcp_listener = std::net::TcpListener::bind(args.council_listen)
        .with_context(|| format!("binding council port {}", args.council_listen))?;

    let council_state = state.clone();
    std::thread::Builder::new()
        .name("council-port".to_string())
        .spawn(move || council::serve_council(tcp_listener, council_state))
        .context("spawning council port thread")?;

    serve(unix_listener, method_acl, move |request| {
        dispatch::dispatch(&state, request)
    });
    unreachable!("custodian socket serve loop never returns");
}

/// Newtype so clap's value_parser has a concrete Clone target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CouncilAddress([u8; 20]);

/// `0x`-prefixed Ethereum address hex (checksum capitalization not
/// enforced) → 20 bytes.
fn parse_council_address(value: &str) -> Result<CouncilAddress> {
    let hex_str = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("council address must start with 0x"))?;
    let bytes = hex::decode(hex_str).context("council address is not valid hex")?;
    let address: [u8; 20] = bytes
        .try_into()
        .map_err(|b: Vec<u8>| anyhow!("council address must be 20 bytes, got {}", b.len()))?;
    Ok(CouncilAddress(address))
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn args_parse() {
        Args::command().debug_assert();
    }

    #[test]
    fn council_address_parses_and_rejects() {
        // Mixed-case (EIP-55 style) input is accepted as plain hex.
        let parsed = parse_council_address("0xAe72A48c1a36bd18Af168541c53037965d26e4A8").unwrap();
        assert_eq!(
            hex::encode(parsed.0),
            "ae72a48c1a36bd18af168541c53037965d26e4a8"
        );

        assert!(parse_council_address("ae72a48c1a36bd18af168541c53037965d26e4a8").is_err());
        assert!(parse_council_address("0xzz").is_err());
        assert!(parse_council_address("0x0011").is_err());
    }
}
