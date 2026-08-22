use alloy_primitives::B256;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use serde::{Deserialize, Serialize};

/// Operator-facing status surface of the attestation service:
///
/// - liveness of the service itself,
/// - first-boot disk-provisioning progress,
/// - whether admission is reading this network's chain.
///
/// Each answers a question only this node's operator acts on, which is what
/// separates them from the peer-facing methods. Consumers speak raw JSON-RPC
/// over HTTP (the deploy CLI, health probes); the generated Rust client exists
/// for tests.
#[rpc(client, server)]
pub trait NodeStatusRpc {
    /// Health check endpoint that returns "OK" if service is running
    #[method(name = "healthCheck")]
    async fn health_check(&self) -> RpcResult<String>;

    /// Report first-boot LUKS provisioning progress.
    ///
    /// First boot wipes the entire persistent disk to seed dm-integrity tags,
    /// which can take 1h+ and is otherwise opaque to the operator. The deploy
    /// CLI polls this to render a progress bar; it returns
    /// [`LuksProvisioningStatus::Idle`] whenever no wipe is in flight (not
    /// started, or already finished). The attestation service is the only
    /// HTTP-serving process alive for the whole wipe, which is why it hosts
    /// this.
    #[method(name = "getLuksProvisioningStatus")]
    async fn get_luks_provisioning_status(&self) -> RpcResult<LuksProvisioningStatus>;

    /// Report whether this node's admission gate is reading the chain its
    /// network manifest commits to.
    ///
    /// Admission denies every join while local reth serves a foreign genesis,
    /// and the only party who can repair that is this node's operator — a
    /// requester cannot. So the detail is reported here, where operators
    /// already look, rather than in the answer a refused joiner gets.
    #[method(name = "getAdmissionChainStatus")]
    async fn get_admission_chain_status(&self) -> RpcResult<AdmissionChainStatus>;
}

// TODO: this is intentionally scoped to just the first-boot LUKS wipe - the one
// long, opaque phase the operator CLI needs a progress bar for. If we later want
// a full node boot-status surface, this would grow into a richer enum covering
// all states: distinguishing wipe-done from never-started, plus the other boot
// phases (root_key fetch / LUKS unlock / summit keygen / ready). Kept minimal
// for now; revisit if the CLI needs more than "is the disk still being wiped?"
/// First-boot LUKS-wipe progress, published by the `setup-persistent-luks`
/// script to a tmpfs file and served by the attestation service.
/// <https://github.com/SeismicSystems/seismic-images/blob/seismic/modules/seismic/mkosi.extra/usr/bin/setup-persistent-luks>
///
/// Internally tagged by `state` so the JSON matches what the script
/// hand-writes (e.g. `{"state":"provisioning","bytes_done":..,"bytes_total":..}`).
/// Only `provisioning`/`error` are ever written to the file; `Idle`/`Unknown`
/// are synthesized by the reader (and still serialized to the CLI).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LuksProvisioningStatus {
    /// No wipe in flight: the status file is absent. Deliberately conflates
    /// "finished" (the script removes the file when done) with "never started"
    /// (a later boot that takes the fast unlock path) - the consumer reacts to
    /// both the same way: no bar, poll the node's real endpoints for readiness.
    Idle,
    /// The wipe is running. `bytes_done`/`bytes_total` drive the progress bar;
    /// a `bytes_total` of 0 means "just started, no measurement yet"
    /// (the CLI should show an indeterminate state until the first real tick).
    Provisioning {
        bytes_done: u64,
        bytes_total: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        eta_seconds: Option<u64>,
    },
    /// The wipe failed; systemd is retrying `persistent-luks-setup.service`.
    Error { error: String },
    /// The status file exists but couldn't be read or parsed - a producer bug
    /// or a perms/IO issue, NOT evidence the wipe finished. The consumer should
    /// surface a warning and keep polling, never treat this as "done".
    Unknown,
}

/// Local reth's genesis block against the one this node's network manifest
/// pins (`eth.genesis_hash`) — the precondition every admission decision
/// re-checks before it reads the on-chain policy.
///
/// Computed per call, never cached or checked at startup: reth comes up after
/// this service, so this must be able to answer `Matches` later without a
/// restart. Every field is public network data — the pin is in the manifest
/// and block 0 is served on the node's public `/rpc` — so an unauthenticated
/// caller learns nothing here it could not compute itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AdmissionChainStatus {
    /// Local reth serves the pinned genesis: admission is deciding joins on
    /// this network's chain, by the live policy it carries.
    Matches { genesis: B256 },
    /// Local reth serves some other chain, so this node admits nobody until an
    /// operator boots it from this network's genesis. Terminal — waiting
    /// changes nothing, and a re-provision is the fix.
    GenesisMismatch { expected: B256, found: B256 },
    /// Local reth did not answer, so which chain it serves is unknown — not
    /// evidence of a mismatch. Expected during the boot tail (reth starts
    /// after this service) and across a reth restart; `error` carries this
    /// node's own failed query.
    RethUnreachable { error: String },
}
