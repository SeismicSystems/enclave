//! Message types for the council delivery port.
//!
//! Everything crosses the wire as CBOR over the same 4-byte length-prefixed
//! framing as the custodian Unix socket; byte fields are tagged `serde_bytes`
//! so they encode as native byte strings. The envelope carries only
//! signed-and-AEAD-sealed material — nothing in this module is secret, which
//! is what makes envelopes safe to persist verbatim.

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Which purpose key a delivery rotates. LUKS `Storage` and `LuksHeaderMac`
/// are deliberately not deliverable: they are local-disk keys pinned at
/// epoch 0 forever (rotating them would mean re-encrypting the disk).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryPurpose {
    TxIo,
    RngPrecompile,
    Snapshot,
}

impl DeliveryPurpose {
    pub const ALL: [DeliveryPurpose; 3] = [
        DeliveryPurpose::TxIo,
        DeliveryPurpose::RngPrecompile,
        DeliveryPurpose::Snapshot,
    ];

    /// Short label matching the corresponding `KeyPurpose` label; also the
    /// on-disk directory name for persisted envelopes.
    pub fn label(&self) -> &'static str {
        match self {
            DeliveryPurpose::TxIo => "tx-io",
            DeliveryPurpose::RngPrecompile => "rng-precompile",
            DeliveryPurpose::Snapshot => "snapshot",
        }
    }

    /// Fixed-length stand-in for the purpose in binding digests, per the
    /// binding layout rule (only fixed-length fields before the tail).
    pub fn binding_tag(&self) -> u8 {
        match self {
            DeliveryPurpose::TxIo => 0x01,
            DeliveryPurpose::RngPrecompile => 0x02,
            DeliveryPurpose::Snapshot => 0x03,
        }
    }
}

/// The signed portion of a delivery: everything the council attests to.
///
/// Carries the purpose key in PLAINTEXT: confidentiality in transit is the
/// deployment's affair (a TLS terminator or tunnel in front of the council
/// port — the centralized phase runs among known operators), and at rest an
/// envelope file is itself a secret. Zeroized on drop; `Debug` redacts.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DeliveryPayload {
    /// Network this delivery is for; rejected elsewhere (anti-replay across
    /// networks).
    #[zeroize(skip)]
    #[serde(with = "serde_bytes")]
    pub network_id: [u8; 32],
    #[zeroize(skip)]
    pub purpose: DeliveryPurpose,
    #[zeroize(skip)]
    pub epoch: u64,
    /// The 32-byte purpose key itself. The council signature covers its
    /// keccak-256 commitment, so the wallet never sees these bytes.
    #[serde(with = "serde_bytes")]
    pub key: [u8; 32],
}

impl fmt::Debug for DeliveryPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeliveryPayload")
            .field("network_id", &self.network_id)
            .field("purpose", &self.purpose)
            .field("epoch", &self.epoch)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// One council delivery: payload plus an Ethereum-wallet signature —
/// 65-byte `r || s || v` recoverable ECDSA over the EIP-712 typed-data
/// digest [`crate::eip712::payload_digest`]. Verification recovers the
/// signer and compares it to the configured council address. Sealing is
/// deterministic (RFC 6979, no randomness), so re-sealing the same payload
/// reproduces the identical envelope — which is what makes retries
/// idempotent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDeliveryEnvelope {
    pub payload: DeliveryPayload,
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 65],
}

/// What an observer custodian asks its parent for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObserverQuery {
    /// The parent's 32-byte root key (epoch-0 derivations).
    RootKey,
    /// Delivered envelopes for `purpose`, ascending from `from_epoch`, at
    /// most [`MAX_ENVELOPES_PER_FETCH`] per response — the reply names the
    /// parent's highest delivered epoch so the client knows whether to page
    /// again.
    Envelopes {
        purpose: DeliveryPurpose,
        from_epoch: u64,
    },
}

/// The signed portion of an observer fetch: everything the child key attests
/// to. The signature additionally covers a connection-local single-use nonce
/// (see `observer_fetch_signing_payload`), which is what makes a captured
/// request worthless to replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserverFetchRequest {
    /// Network this fetch is for; rejected elsewhere (anti-replay across
    /// networks).
    #[serde(with = "serde_bytes")]
    pub network_id: [u8; 32],
    /// Which child of the parent's master key signed this. Any index is
    /// acceptable — only the master-key holder can sign as any child — so
    /// the index merely tells the parent which pubkey to derive.
    pub observer_index: u32,
    pub query: ObserverQuery,
}

/// Caps one `Envelopes` response well under the 64 KiB frame limit
/// (an envelope is ~190 bytes of CBOR; pinned by test).
pub const MAX_ENVELOPES_PER_FETCH: usize = 64;

/// The parent's root key in transit to an observer. Plaintext for the same
/// reason envelopes are: transport confidentiality is the fronting
/// TLS/tunnel's job. Zeroized on drop; `Debug` redacts.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ObserverRootKey {
    #[serde(with = "serde_bytes")]
    pub key: [u8; 32],
}

impl fmt::Debug for ObserverRootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObserverRootKey")
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Why an observer fetch was refused. Stable, sanitized vocabulary — detail
/// stays in the parent's local logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObserverRejectCode {
    /// This custodian has no `--summit-key-dir`, so it cannot verify (and
    /// does not serve) observer fetches.
    NotServingObservers,
    /// No unconsumed challenge on this connection: ask for one first (each
    /// nonce authorizes exactly one fetch).
    MissingChallenge,
    WrongNetwork,
    BadSignature,
}

/// One request over the council delivery port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CouncilRequest {
    /// Liveness probe.
    Ping,
    /// Public delivery state: what the council needs before sealing the next
    /// envelope (next expected epochs, readiness).
    GetStatus,
    /// Install one epoch key. Authentication is the signature inside the
    /// envelope, not the transport.
    DeliverEpochKey(SignedDeliveryEnvelope),
    /// Ask for a single-use nonce to sign into the next `ObserverFetch` on
    /// this connection.
    ObserverChallenge,
    /// Fetch the root key or delivered envelopes, signed by a child key
    /// derived from the parent's master node key. Authentication is the
    /// ed25519 signature over the challenge nonce and the request, not the
    /// transport.
    ObserverFetch {
        request: ObserverFetchRequest,
        #[serde(with = "serde_bytes")]
        signature: [u8; 64],
    },
}

impl CouncilRequest {
    /// Stable label for logging.
    pub fn method(&self) -> &'static str {
        match self {
            CouncilRequest::Ping => "ping",
            CouncilRequest::GetStatus => "get_status",
            CouncilRequest::DeliverEpochKey(_) => "deliver_epoch_key",
            CouncilRequest::ObserverChallenge => "observer_challenge",
            CouncilRequest::ObserverFetch { .. } => "observer_fetch",
        }
    }
}

/// Why a delivery was refused. Stable, sanitized vocabulary — detail stays in
/// the custodian's local logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectCode {
    WrongNetwork,
    BadSignature,
    /// Epochs are sequential per purpose; the message names the expected one.
    NonSequentialEpoch,
    /// A different envelope already holds this epoch.
    EpochConflict,
    /// The key bytes are not usable for the purpose.
    InvalidKey,
    /// Verified but could not be made durable; nothing was installed.
    PersistFailed,
}

/// Public delivery state: everything the council needs before sealing the
/// next envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CouncilStatus {
    #[serde(with = "serde_bytes")]
    pub network_id: [u8; 32],
    /// Highest delivered epoch per purpose; 0 = only the derived epoch 0
    /// exists, so the next delivery is epoch 1.
    pub tx_io_epoch: u64,
    pub rng_epoch: u64,
    pub snapshot_epoch: u64,
}

/// One response over the council delivery port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CouncilResponse {
    Pong,
    Status(CouncilStatus),
    Delivered {
        purpose: DeliveryPurpose,
        epoch: u64,
    },
    /// Byte-identical redelivery of an already-installed epoch: idempotent
    /// success, nothing changed.
    AlreadyDelivered {
        purpose: DeliveryPurpose,
        epoch: u64,
    },
    Rejected {
        code: RejectCode,
        message: String,
    },
    /// A single-use nonce for the next `ObserverFetch` on this connection.
    Challenge {
        #[serde(with = "serde_bytes")]
        nonce: [u8; 32],
    },
    /// The parent's root key, answering `ObserverQuery::RootKey`.
    RootKey(ObserverRootKey),
    /// Delivered envelopes, answering `ObserverQuery::Envelopes`.
    Envelopes {
        envelopes: Vec<SignedDeliveryEnvelope>,
        /// The parent's highest delivered epoch for the purpose — page again
        /// from the last envelope's epoch + 1 while below this.
        delivered_epoch: u64,
    },
    ObserverRejected {
        code: ObserverRejectCode,
        message: String,
    },
}

impl CouncilResponse {
    /// Stable label for logging.
    pub fn kind(&self) -> &'static str {
        match self {
            CouncilResponse::Pong => "pong",
            CouncilResponse::Status(_) => "status",
            CouncilResponse::Delivered { .. } => "delivered",
            CouncilResponse::AlreadyDelivered { .. } => "already_delivered",
            CouncilResponse::Rejected { .. } => "rejected",
            CouncilResponse::Challenge { .. } => "challenge",
            CouncilResponse::RootKey(_) => "root_key",
            CouncilResponse::Envelopes { .. } => "envelopes",
            CouncilResponse::ObserverRejected { .. } => "observer_rejected",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte fields must encode as CBOR byte strings (major type 2), not
    /// integer arrays — the same guarantee custodian-ipc pins for its wire.
    #[test]
    fn envelope_bytes_encode_as_cbor_byte_strings() {
        let envelope = SignedDeliveryEnvelope {
            payload: DeliveryPayload {
                network_id: [0x11; 32],
                purpose: DeliveryPurpose::TxIo,
                epoch: 1,
                key: [0x44; 32],
            },
            signature: [0x55; 65],
        };
        let mut wire = Vec::new();
        ciborium::into_writer(&envelope, &mut wire).unwrap();
        // 0x58 0x20 = byte string, one-byte length 32.
        let marker: &[u8] = &[0x58, 0x20, 0x11];
        assert!(
            wire.windows(3).any(|w| w == marker),
            "network_id must encode as a byte string"
        );
        let decoded: SignedDeliveryEnvelope = ciborium::from_reader(wire.as_slice()).unwrap();
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn payload_debug_redacts_the_key() {
        let payload = DeliveryPayload {
            network_id: [0x11; 32],
            purpose: DeliveryPurpose::TxIo,
            epoch: 1,
            key: [0xA5; 32],
        };
        let debug = format!("{payload:?}");
        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(!debug.contains("165"), "key leaked: {debug}");
    }

    #[test]
    fn observer_root_key_debug_redacts() {
        let root = ObserverRootKey { key: [0xA5; 32] };
        let debug = format!("{root:?}");
        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(!debug.contains("165"), "key leaked: {debug}");
    }

    /// A full envelope batch must fit one frame: MAX_ENVELOPES_PER_FETCH is
    /// only a valid cap if the worst-case `Envelopes` response encodes under
    /// the 64 KiB frame body limit shared with custodian-ipc.
    #[test]
    fn max_envelope_batch_fits_one_frame() {
        const MAX_FRAME_BODY_LEN: usize = 64 * 1024; // custodian-ipc framing cap
        let envelope = SignedDeliveryEnvelope {
            payload: DeliveryPayload {
                network_id: [0xFF; 32],
                purpose: DeliveryPurpose::RngPrecompile, // longest label
                epoch: u64::MAX,
                key: [0xFF; 32],
            },
            signature: [0xFF; 65],
        };
        let response = CouncilResponse::Envelopes {
            envelopes: vec![envelope; MAX_ENVELOPES_PER_FETCH],
            delivered_epoch: u64::MAX,
        };
        let mut wire = Vec::new();
        ciborium::into_writer(&response, &mut wire).unwrap();
        assert!(
            wire.len() < MAX_FRAME_BODY_LEN,
            "max batch is {} bytes, frame cap is {}",
            wire.len(),
            MAX_FRAME_BODY_LEN
        );
    }

    #[test]
    fn purpose_labels_and_tags_are_distinct() {
        for (i, a) in DeliveryPurpose::ALL.iter().enumerate() {
            for b in &DeliveryPurpose::ALL[i + 1..] {
                assert_ne!(a.label(), b.label());
                assert_ne!(a.binding_tag(), b.binding_tag());
            }
        }
    }
}
