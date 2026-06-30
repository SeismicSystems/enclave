use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use serde::{Deserialize, Serialize};

#[rpc(client, server)]
pub trait TdxQuoteRpc {
    /// Health check endpoint that returns "OK" if service is running
    #[method(name = "healthCheck")]
    async fn health_check(&self) -> RpcResult<String>;

    /// Get the secp256k1 public key
    #[method(name = "getPurposeKeys")]
    async fn get_purpose_keys(&self, epoch: u64) -> RpcResult<GetPurposeKeysResponse>;

    /// Generates attestation evidence from the attestation authority
    #[method(name = "getAttestationEvidence")]
    async fn get_attestation_evidence(&self) -> RpcResult<AttestationGetEvidenceResponse>;

    /// Evaluates provided attestation evidence
    #[method(name = "evalAttestationEvidence")]
    async fn eval_attestation_evidence(&self, hcl_report: Vec<u8>, quote: Vec<u8>)
    -> RpcResult<()>;

    /// Get the network root key from an existing node, wrapped to this caller.
    ///
    /// Called by a booting/joining node on a peer that already holds the
    /// network root key. `request` is a serialized [`RootKeyRequest`] carrying
    /// the caller's attested ephemeral key + nonce, and the reply is a
    /// serialized [`RootKeyResponse`] carrying the root key AEAD-wrapped under
    /// an ECDH key bound into the attested transcript.
    ///
    /// The wire body is opaque bytes here so this crate need not depend on the
    /// attestation stack.
    ///
    /// [`RootKeyRequest`]: ../../enclave-server/src/bootstrap.rs
    /// [`RootKeyResponse`]: ../../enclave-server/src/bootstrap.rs
    #[method(name = "getWrappedRootKey")]
    async fn get_wrapped_root_key(&self, request: Vec<u8>) -> RpcResult<Vec<u8>>;

    /// Report first-boot LUKS provisioning progress.
    ///
    /// First boot wipes the entire persistent disk to seed dm-integrity tags,
    /// which can take 1h+ and is otherwise opaque to the operator. The deploy
    /// CLI polls this to render a progress bar; it returns
    /// [`LuksProvisioningStatus::Idle`] whenever no wipe is in flight (not
    /// started, or already finished). enclave-server is the only node service
    /// alive for the whole wipe, which is why it hosts this.
    #[method(name = "getLuksProvisioningStatus")]
    async fn get_luks_provisioning_status(&self) -> RpcResult<LuksProvisioningStatus>;
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetPurposeKeysResponse {
    pub tx_io_sk: secp256k1::SecretKey,
    pub tx_io_pk: secp256k1::PublicKey,
    pub snapshot_key_bytes: [u8; 32],
    pub rng_keypair: schnorrkel::keys::Keypair,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttestationGetEvidenceResponse {
    pub hcl_report: Vec<u8>,
    pub quote: Vec<u8>,
}

// TODO: this is intentionally scoped to just the first-boot LUKS wipe — the one
// long, opaque phase the operator CLI needs a progress bar for. If we later want
// a full node boot-status surface, this would grow into a richer enum covering
// all states: distinguishing wipe-done from never-started, plus the other boot
// phases (root_key fetch / LUKS unlock / summit keygen / ready). Kept minimal
// for now; revisit if the CLI needs more than "is the disk still being wiped?".
/// First-boot LUKS-wipe progress, published by the `setup-persistent-luks`
/// script to a tmpfs file and served by enclave-server.
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
    /// (a later boot that takes the fast unlock path) — the consumer reacts to
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
    /// The status file exists but couldn't be read or parsed — a producer bug
    /// or a perms/IO issue, NOT evidence the wipe finished. The consumer should
    /// surface a warning and keep polling, never treat this as "done".
    Unknown,
}
