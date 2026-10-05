mod admission;
pub mod api;
pub mod bootstrap;
pub mod conf;
pub mod harvest;
mod join;
mod luks_status;
mod network;
pub mod rpc_error;
mod server;
pub mod utils;

/// Attestation type this build mints and verifies evidence for. Azure TDX +
/// vTPM is the only supported type today. Both roles hold to it: the evidence
/// this node mints for its own join, and the evidence it accepts from nodes
/// joining after it.
pub(crate) const ATTESTATION_TYPE: seismic_attestation::AttestationType =
    seismic_attestation::AttestationType::AzureTdx;

/// Both listeners default to loopback as the safe choice; a node binds
/// `0.0.0.0` and the cloud firewall decides who reaches each port.
const DEFAULT_PEER_LISTEN: &str = "127.0.0.1:7878";
const DEFAULT_OPERATOR_LISTEN: &str = "127.0.0.1:7879";
/// The node's own reth, assumed to serve HTTP JSON-RPC on the conventional
/// loopback endpoint.
const DEFAULT_RETH_RPC_URL: &str = "http://127.0.0.1:8545";

use anyhow::Result;
use clap::Parser;
use seismic_custodian_ipc::DEFAULT_CUSTODIAN_SOCKET_PATH;
use std::{net::SocketAddr, path::PathBuf};
use tracing::info;

/// Command line arguments for the attestation service
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// The JSON-RPC listener joining peers fetch the root key from, which
    /// also serves the node's other public RPCs: tx-io evidence, deploy
    /// verification, status. It binds only once the custodian holds
    /// `root_key`, so an open port is the readiness signal. A node opens it
    /// to anyone: peers that join later dial it from addresses nobody knows
    /// in advance.
    #[arg(long, default_value = DEFAULT_PEER_LISTEN)]
    pub peer_listen: SocketAddr,

    /// The listener only the operator may reach, up from boot: the founding
    /// harvest, summit's pubkeys and a quote over them until the network
    /// manifest exists. A node's firewall restricts it to the operator's
    /// CIDR, permanently, since the quote window reopens every boot.
    #[arg(long, default_value = DEFAULT_OPERATOR_LISTEN)]
    pub operator_listen: SocketAddr,

    /// Filesystem path for the custodian IPC socket.
    #[arg(long, default_value = DEFAULT_CUSTODIAN_SOCKET_PATH)]
    pub custodian_socket: PathBuf,

    /// tdx-init's config drop-zone. The service waits for tdx-init's done
    /// marker there before anything past the harvest, then reads the
    /// root-key peers and the network manifest from it.
    #[arg(long, default_value = conf::DEFAULT_CONF_DIR)]
    pub conf_dir: PathBuf,

    /// HTTP JSON-RPC endpoint of this node's own reth, queried to check each
    /// joining peer's admission ID against the on-chain MeasurementRegistry.
    /// An unreachable endpoint denies joins (fail closed) — it never blocks
    /// this service's startup or its other RPCs.
    #[arg(long, env = "SEISMIC_RETH_RPC_URL", default_value = DEFAULT_RETH_RPC_URL)]
    pub reth_rpc_url: url::Url,

    /// Bound on the finalized-block age admission decisions accept; `None`
    /// keeps the production default. Deliberately not a CLI flag: only the
    /// admission integration suite tightens it, to observe the staleness
    /// denial without waiting out the production bound.
    #[arg(skip)]
    pub max_policy_age: Option<std::time::Duration>,
}

impl Args {
    pub async fn start(self) -> Result<()> {
        // Quote verification's collateral fetching (attested-tls) builds
        // rustls-backed HTTP clients, which need a process-level crypto
        // provider that only the application can choose. Install it before
        // anything verifies evidence; a provider installed even earlier by
        // an embedding process wins, and any provider serves.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let listener = tokio::net::TcpListener::bind(self.operator_listen).await?;
        info!("Serving the founding harvest on {}", self.operator_listen);
        let harvest = harvest::serve(
            listener,
            harvest::Harvest::new(
                harvest::SUMMIT_PUBLIC_KEYS_PATH.into(),
                self.conf_dir.join(conf::NETWORK_MANIFEST),
            ),
        );

        tokio::select! {
            result = harvest => result,
            result = self.run_node() => result,
        }
    }

    /// Everything past the harvest: the manifest, `root_key`, and the
    /// JSON-RPC server.
    async fn run_node(self) -> Result<()> {
        let peers = conf::await_config(&self.conf_dir).await?;

        let addr = self.peer_listen;
        info!("Starting attestation-service JSON-RPC server on {addr}...");

        server::start_server(addr, self, &peers).await
    }
}
