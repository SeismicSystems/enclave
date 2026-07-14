//! Wire protocol, client, and server for the key-custodian Unix socket.
//!
//! Framing is a 4-byte big-endian length prefix followed by a CBOR body
//! ([`framing`]); messages are the byte-oriented [`Request`]/[`Response`]
//! serde enums.
//! This crate is both ends of the custodian wire surface, feature-gated by
//! what each host needs:
//!
//! - core (always): wire types + pure/blocking framing — serde, ciborium,
//!   zeroize only
//! - `client` (default): async [`CustodianClient`] for tokio hosts (reth,
//!   the attestation service)
//! - `server`: the synchronous socket server in [`server`] — no async
//!   runtime, for the process that holds the keys
//!
//! Boundary rule: this crate stays a leaf — no custodian, attestation, or
//! crypto-stack dependencies. Key material crosses the wire as raw bytes and
//! callers convert to typed keys on their side; the server takes dispatch as
//! an injected closure rather than knowing the custodian. Linking any part
//! of this crate never drags the enclave stack into a consumer.

#[cfg(feature = "client")]
mod client;
mod error;
pub mod framing;
mod messages;
#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub use client::{
    CreateRootKeyBootstrapAttemptResult, CustodianClient,
    InstallRootKeyFromVerifiedBootstrapResponseResult,
};
pub use error::IpcError;
// The pure encode/decode internals stay crate-private; consumers frame
// messages through these I/O functions (or the client/server above them).
// Re-exporting more later is additive, so start minimal — this crate's API
// gets pinned by consumers at the process split.
pub use framing::{MAX_FRAME_BODY_LEN, read_frame_blocking, write_frame_blocking};
#[cfg(feature = "client")]
pub use framing::{read_frame, write_frame};
pub use messages::{
    Request, Response, RngKeypairBytes, RootKeyBootstrapAttemptBytes, SnapshotKeyBytes,
    TxIoKeypairBytes, TxIoPublicKeyBytes, WrappedRootKeyBytes,
};

/// Where enclave-server hosts the custodian socket on a node. `/run/seismic`
/// is tmpfs, created by tdx-init before enclave-server starts.
pub const CUSTODIAN_SOCKET_PATH: &str = "/run/seismic/custodian.sock";
