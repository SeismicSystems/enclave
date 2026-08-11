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
use seismic_custodian::Custodian;
use seismic_custodian_ipc::DEFAULT_CUSTODIAN_SOCKET_PATH;
use seismic_custodian_ipc::server::{bind, serve};
use seismic_custodian_service::acl;
use seismic_network_manifest::NetworkId;
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

    /// Path of the 32-byte root keyfile; generated (mode 0600) on first
    /// boot if absent. Back it up: epoch-0 keys and the council inbox key
    /// derive from it.
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

    /// The security council's secp256k1 public key (0x + 66 hex chars,
    /// compressed SEC1). Every delivery envelope must be signed by it.
    #[arg(long, env = "SEISMIC_COUNCIL_PUBKEY", value_parser = parse_council_pubkey)]
    council_pubkey: secp256k1::PublicKey,

    /// Path to the network manifest whose bytes define this network's id.
    #[arg(long, env = "SEISMIC_NETWORK_MANIFEST")]
    network_manifest: PathBuf,

    /// Directory where delivery envelopes persist (signed + encrypted;
    /// never plaintext keys).
    #[arg(long, default_value = DEFAULT_DELIVERY_DIR)]
    delivery_dir: PathBuf,
}

fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    // Everything that can be misconfigured fails here, before the sockets
    // exist: ACL grants, the manifest, the delivery store, the keyfile.
    let method_acl = acl::method_acl_from_allow_specs(&args.allow)
        .context("resolving --allow grants (is the user missing?)")?;
    let manifest_bytes = std::fs::read(&args.network_manifest)
        .with_context(|| format!("reading {}", args.network_manifest.display()))?;
    let network_id = NetworkId::from_manifest_bytes(&manifest_bytes);
    info!(%network_id, "delivery envelopes must be bound to this network");

    let root_key = root_key_file::load_or_generate(&args.root_key_file)?;
    let state = Arc::new(
        CentralizedCustodianState::new(
            Custodian::new(root_key),
            args.delivery_dir,
            args.council_pubkey,
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

/// `0x`-prefixed compressed SEC1 hex → a secp256k1 public key.
fn parse_council_pubkey(value: &str) -> Result<secp256k1::PublicKey> {
    let hex_str = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("council pubkey must start with 0x"))?;
    let bytes = hex::decode(hex_str).context("council pubkey is not valid hex")?;
    if bytes.len() != 33 {
        return Err(anyhow!(
            "council pubkey must be 33 bytes (compressed SEC1), got {}",
            bytes.len()
        ));
    }
    secp256k1::PublicKey::from_slice(&bytes).context("council pubkey is not a valid curve point")
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
    fn council_pubkey_parses_and_rejects() {
        let sk = secp256k1::SecretKey::from_byte_array(&[0x77; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk);
        let hex_pk = format!("0x{}", hex::encode(pk.serialize()));
        assert_eq!(parse_council_pubkey(&hex_pk).unwrap(), pk);

        assert!(parse_council_pubkey(hex_pk.trim_start_matches("0x")).is_err());
        assert!(parse_council_pubkey("0xzz").is_err());
        assert!(parse_council_pubkey("0x0011").is_err());
        // 33 bytes that are not a curve point.
        assert!(parse_council_pubkey(&format!("0x{}", hex::encode([0u8; 33]))).is_err());
    }
}
