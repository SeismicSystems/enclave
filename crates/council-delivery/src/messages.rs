//! Message types for the council delivery port.
//!
//! Everything crosses the wire as CBOR over the same 4-byte length-prefixed
//! framing as the custodian Unix socket; byte fields are tagged `serde_bytes`
//! so they encode as native byte strings. The envelope carries only
//! signed-and-AEAD-sealed material — nothing in this module is secret, which
//! is what makes envelopes safe to persist verbatim.

use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryPayload {
    /// Network this delivery is for; rejected elsewhere (anti-replay across
    /// networks).
    #[serde(with = "serde_bytes")]
    pub network_id: [u8; 32],
    pub purpose: DeliveryPurpose,
    pub epoch: u64,
    /// Council-side ephemeral ECDH pubkey, fresh per envelope.
    #[serde(with = "serde_bytes")]
    pub sender_eph_pk: [u8; 33],
    /// The custodian inbox pubkey this ciphertext was sealed to.
    #[serde(with = "serde_bytes")]
    pub inbox_pk: [u8; 33],
    /// `nonce(12) || AES-256-GCM ciphertext+tag` over the 32-byte purpose key.
    #[serde(with = "serde_bytes")]
    pub encrypted_key: Vec<u8>,
}

/// One council delivery: payload plus a compact ECDSA signature by the
/// council key over `bindings::delivery_binding(&payload)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDeliveryEnvelope {
    pub payload: DeliveryPayload,
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
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
    /// The inbox key is derived from the root key, which is not present yet;
    /// retry after the node bootstraps.
    RootKeyAbsent,
    /// The persistent delivery store is not mountable yet; retry later. A
    /// delivery that cannot be persisted is never accepted.
    PersistenceUnavailable,
    WrongNetwork,
    /// `payload.inbox_pk` is not this custodian's inbox.
    WrongRecipient,
    BadSignature,
    /// Epochs are sequential per purpose; the message names the expected one.
    NonSequentialEpoch,
    /// A different envelope already holds this epoch.
    EpochConflict,
    /// AEAD open failed.
    DecryptFailed,
    /// The decrypted bytes are not a usable key for the purpose.
    InvalidKey,
    /// Verified but could not be made durable; nothing was installed.
    PersistFailed,
}

/// Public delivery state, answered even before the node is ready to accept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CouncilStatus {
    #[serde(with = "serde_bytes")]
    pub network_id: [u8; 32],
    /// `None` until the root key is present (the inbox key derives from it).
    pub inbox_pk: Option<InboxPk>,
    /// Highest delivered epoch per purpose; 0 = only the derived epoch 0
    /// exists, so the next delivery is epoch 1.
    pub tx_io_epoch: u64,
    pub rng_epoch: u64,
    pub snapshot_epoch: u64,
    /// True only when the root key is present AND the delivery store is
    /// writable — the two preconditions for `DeliverEpochKey` to succeed.
    pub accepting_deliveries: bool,
}

/// Wrapper so the optional inbox pubkey still encodes as a CBOR byte string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxPk(#[serde(with = "serde_bytes")] pub [u8; 33]);

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
                sender_eph_pk: [0x22; 33],
                inbox_pk: [0x33; 33],
                encrypted_key: vec![0x44; 60],
            },
            signature: [0x55; 64],
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
    fn purpose_labels_and_tags_are_distinct() {
        for (i, a) in DeliveryPurpose::ALL.iter().enumerate() {
            for b in &DeliveryPurpose::ALL[i + 1..] {
                assert_ne!(a.label(), b.label());
                assert_ne!(a.binding_tag(), b.binding_tag());
            }
        }
    }
}
