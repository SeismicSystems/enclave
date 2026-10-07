//! `seismic-custodian-service` — the standalone service for the network root key.
//!
//! Owns the [`Custodian`]'s root key in process memory and serves derivation
//! and wrapping to local callers over a Unix socket, each authenticated by
//! kernel-reported UID (`SO_PEERCRED`) against the `--allow` grants. The
//! process is kept explicitly minimal — a synchronous socket server with a
//! tiny dependency footprint — to reduce the attack surface around the root
//! key; see the `seismic-custodian` crate docs for the boundary rule.

use anyhow::{Context as _, Result};
use clap::Parser;
use seismic_custodian::Custodian;
use seismic_custodian_ipc::DEFAULT_CUSTODIAN_SOCKET_PATH;
use seismic_custodian_ipc::candidate_tx_io_pk;
use seismic_custodian_ipc::server::{bind, serve};
use seismic_custodian_service::{acl, dispatch, state::CustodianState};
use std::path::{Path, PathBuf};
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Default drop-zone for the LUKS keyfile, in this service's runtime
/// directory. The path is a deployment contract with `setup-persistent-luks`
/// (seismic-images), which polls for the file and shreds it after use.
const DEFAULT_LUKS_KEYFILE_PATH: &str = "/run/seismic/custodian/luks-keys";

/// Where tdx-init drops the verbatim manifest at the config POST. Mirrors
/// tdx-init's `CONF_DIR`/`network-manifest.json`.
const DEFAULT_NETWORK_MANIFEST_PATH: &str = "/run/seismic/conf/network-manifest.json";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Filesystem path for the custodian IPC socket.
    #[arg(long, default_value = DEFAULT_CUSTODIAN_SOCKET_PATH)]
    socket: PathBuf,

    /// The network manifest tdx-init writes at the config POST. Its
    /// `founding_tx_io_pk` decides whether this custodian keeps the candidate
    /// it minted at startup, and which fetched key it may install.
    #[arg(long, default_value = DEFAULT_NETWORK_MANIFEST_PATH)]
    network_manifest: PathBuf,

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
             --allow attestation:tx-io-public,create-root-key-bootstrap-attempt,\
             wrap-root-key,retire-founding-policy,\
             install-root-key-from-verified-bootstrap-response",
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

    // Every node mints a candidate before the manifest exists, so the founding
    // harvest can quote its tx_io_pk@0 and assemble can pin one. The state
    // resolves it against the manifest once the config POST has written it,
    // and owns the LUKS keyfile handoff from there.
    let candidate_tx_io_pk_path = Path::new(candidate_tx_io_pk::CANDIDATE_TX_IO_PK_PATH);
    candidate_tx_io_pk::remove_stale(candidate_tx_io_pk_path)
        .with_context(|| format!("removing the stale {}", candidate_tx_io_pk_path.display()))?;
    let candidate = Custodian::mint()?;
    let tx_io_pk = candidate.get_tx_io_pk(0).serialize();
    info!(
        tx_io_pk = %hex::encode(tx_io_pk),
        "minted a candidate root key; awaiting the manifest's pin"
    );
    candidate_tx_io_pk::write(candidate_tx_io_pk_path, &tx_io_pk)
        .with_context(|| format!("writing {}", candidate_tx_io_pk_path.display()))?;
    let state =
        CustodianState::new_with_candidate(candidate, args.network_manifest, args.luks_keyfile);

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
