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

/// One request over the council delivery port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CouncilRequest {
    /// Liveness probe.
    Ping,
    /// Public delivery state: what the council needs before sealing the next
    /// envelope (inbox pubkey, next expected epochs, readiness).
    GetStatus,
    /// Install one epoch key. Authentication is the signature inside the
    /// envelope, not the transport.
    DeliverEpochKey(SignedDeliveryEnvelope),
}

impl CouncilRequest {
    /// Stable label for logging.
    pub fn method(&self) -> &'static str {
        match self {
            CouncilRequest::Ping => "ping",
            CouncilRequest::GetStatus => "get_status",
            CouncilRequest::DeliverEpochKey(_) => "deliver_epoch_key",
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
    fn purpose_labels_and_tags_are_distinct() {
        for (i, a) in DeliveryPurpose::ALL.iter().enumerate() {
            for b in &DeliveryPurpose::ALL[i + 1..] {
                assert_ne!(a.label(), b.label());
                assert_ne!(a.binding_tag(), b.binding_tag());
            }
        }
    }
}
