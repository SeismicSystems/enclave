//! `seismic-key-custodian` — the standalone host for the network root key.
//!
//! Owns the [`Custodian`]'s root key in process memory and serves derivation
//! and wrapping to local callers over a Unix socket, each authenticated by
//! kernel-reported UID (`SO_PEERCRED`) against the `--allow` grants. The
//! process is kept explicitly minimal — a synchronous socket server with a
//! tiny dependency footprint — to reduce the attack surface around the root
//! key; see the `seismic-key-custodian` crate docs for the boundary rule.

use anyhow::{Context as _, Result};
use clap::Parser;
use seismic_custodian_ipc::DEFAULT_CUSTODIAN_SOCKET_PATH;
use seismic_custodian_ipc::server::{bind, serve};
use seismic_key_custodian::Custodian;
use state::CustodianState;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod acl;
mod dispatch;
mod state;

/// Default drop-zone for the LUKS keyfile, in this service's runtime
/// directory. The path is a deployment contract with `setup-persistent-luks`
/// (seismic-images), which polls for the file and shreds it after use.
const DEFAULT_LUKS_KEYFILE_PATH: &str = "/run/seismic/custodian/luks-keys";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Filesystem path for the custodian IPC socket.
    #[arg(long, default_value = DEFAULT_CUSTODIAN_SOCKET_PATH)]
    socket: PathBuf,

    /// Generate a fresh network root key at startup instead of awaiting one
    /// via the bootstrap methods. Set on exactly one node in the deployment;
    /// setting it on multiple nodes causes a silent network split.
    #[arg(long, env = "SEISMIC_CUSTODIAN_GENESIS_NODE", default_value_t = false)]
    genesis_node: bool,

    /// Path the LUKS keyfile is written to once the root key exists
    /// and the LUKS key has been derived from it.
    #[arg(long, default_value = DEFAULT_LUKS_KEYFILE_PATH)]
    luks_keyfile: PathBuf,

    /// Grant a local user custodian methods; repeatable, deny-by-default.
    #[arg(
        long = "allow",
        value_name = "USER:PURPOSES",
        long_help = format!(
            "Grant a local user custodian methods; repeatable, deny-by-default.\n\n\
             Purposes: {}.\n\n\
             The two intended callers and their grants:\n  \
             --allow reth:tx-io,rng\n  \
             --allow enclave-attest:tx-io-public,create-root-key-bootstrap-attempt,\
             wrap-root-key,install-root-key-from-verified-bootstrap-response",
            acl::VALID_PURPOSES
        )
    )]
    allow: Vec<String>,
}

fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    // Resolve grants before any key material exists: an unresolvable user
    // name is a deployment bug and must fail the boot, not become a silent
    // runtime deny.
    let acl = acl::method_acl_from_allow_specs(&args.allow)?;

    // The state owns the LUKS keyfile handoff: it is written whenever the
    // root key becomes present. For a genesis node that is right here — a
    // failure is fatal, since without the keys reaching setup-persistent-luks
    // the node can't proceed past this boot.
    let state = if args.genesis_node {
        info!("genesis node: generating fresh network root key");
        CustodianState::new_with_root_key(Custodian::new_as_genesis()?, args.luks_keyfile)?
    } else {
        info!("joining node: awaiting root key via the bootstrap methods");
        CustodianState::new_awaiting_root_key(args.luks_keyfile)
    };

    let listener = bind(&args.socket)
        .with_context(|| format!("binding custodian socket {}", args.socket.display()))?;
    serve(listener, acl, move |request| {
        dispatch::dispatch(&state, request)
    });
    unreachable!("the custodian accept loop never returns");
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
}
