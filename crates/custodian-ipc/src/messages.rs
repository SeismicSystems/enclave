//! Message types for the custodian socket.
//!
//! Everything crosses the wire as raw bytes — fixed-size arrays for keys and
//! digests, `Vec<u8>` for variable-length blobs — tagged `serde_bytes` so CBOR
//! encodes them as native byte strings. Callers convert to typed keys
//! (`secp256k1`, `schnorrkel`, `aes-gcm`) at their own boundary; see the
//! crate-level boundary rule.
//!
//! Key-fetch methods are deliberately one-per-purpose, never bundled: the
//! method is the unit an ACL grant covers, so each caller can be given
//! exactly the purposes it needs (see `server::MethodAcl` for who gets
//! what), and each purpose keeps an independent epoch so one key can be
//! rotated without touching the others.

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// One request over the custodian socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    /// Liveness probe; carries no key material in either direction.
    Ping,
    /// Derive this epoch's tx-io ECDH keypair (TxSeismic calldata
    /// encryption). Epochs are fixed at 0 until a consensus-driven manual
    /// rotation exists; same for the other purposes below.
    GetTxIoKeypair { epoch: u64 },
    /// Derive this epoch's RNG-precompile keypair.
    GetRngKeypair { epoch: u64 },
    /// Derive this epoch's snapshot encryption key.
    GetSnapshotKey { epoch: u64 },
    /// AEAD-wrap the root key for an attestation-verified peer.
    ///
    /// `root_key_request_binding` is the digest of the request transcript the
    /// *caller* already verified (it becomes the AEAD AAD; the custodian
    /// carries it opaquely). Sending this request asserts that verification
    /// succeeded — the ACL must confine it to the attestation-service.
    WrapRootKey {
        #[serde(with = "serde_bytes")]
        root_key_request_binding: [u8; 32],
        /// Peer's ephemeral ECDH public key, 33-byte compressed SEC1.
        #[serde(with = "serde_bytes")]
        peer_eph_pk: [u8; 33],
    },
}

impl Request {
    /// Stable method label for ACL decisions and log lines.
    pub fn method(&self) -> &'static str {
        match self {
            Request::Ping => "ping",
            Request::GetTxIoKeypair { .. } => "get_tx_io_keypair",
            Request::GetRngKeypair { .. } => "get_rng_keypair",
            Request::GetSnapshotKey { .. } => "get_snapshot_key",
            Request::WrapRootKey { .. } => "wrap_root_key",
        }
    }
}

/// One response; variants mirror [`Request`] plus two failure variants,
/// split by which layer failed the request: [`Response::Denied`] is minted
/// only by the transport's ACL loop, [`Response::Error`] only by the host's
/// dispatch handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Pong,
    TxIoKeypair(TxIoKeypairBytes),
    RngKeypair(RngKeypairBytes),
    SnapshotKey(SnapshotKeyBytes),
    WrappedRootKey(WrappedRootKeyBytes),
    /// The ACL refused this peer the method; the handler never saw the
    /// request. Retrying cannot succeed until the node's ACL changes.
    Denied {
        message: String,
    },
    /// The handler accepted the request but the operation failed (bad
    /// argument or internal error); no partial output is returned.
    Error {
        message: String,
    },
}

/// secp256k1 tx-io keypair as raw bytes. Zeroized on drop: `sk` is a secret.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct TxIoKeypairBytes {
    #[serde(with = "serde_bytes")]
    pub sk: [u8; 32],
    /// 33-byte compressed SEC1 public key.
    #[serde(with = "serde_bytes")]
    pub pk: [u8; 33],
}

// Manual Debug so a stray `{:?}` on a response can't log the secret half.
impl fmt::Debug for TxIoKeypairBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxIoKeypairBytes")
            .field("sk", &"<redacted>")
            .field("pk", &self.pk)
            .finish()
    }
}

/// schnorrkel RNG keypair as raw bytes (`Keypair::to_bytes()`, 96 bytes,
/// secret half included). Zeroized on drop.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RngKeypairBytes {
    #[serde(with = "serde_bytes")]
    pub keypair: Vec<u8>,
}

impl fmt::Debug for RngKeypairBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RngKeypairBytes")
            .field("keypair", &"<redacted>")
            .finish()
    }
}

/// AES-256-GCM snapshot key as raw bytes. Zeroized on drop.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SnapshotKeyBytes {
    #[serde(with = "serde_bytes")]
    pub key: [u8; 32],
}

impl fmt::Debug for SnapshotKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnapshotKeyBytes")
            .field("key", &"<redacted>")
            .finish()
    }
}

/// One wrap operation's output — `WrappedRootKey` from seismic-key-custodian
/// as raw bytes. Not secret: the payload is AEAD-sealed to the peer's
/// ephemeral key and the pubkey is public by definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedRootKeyBytes {
    /// Custodian-side ephemeral ECDH public key, 33-byte compressed SEC1.
    #[serde(with = "serde_bytes")]
    pub responder_eph_pk: [u8; 33],
    /// `nonce(12) || AES-256-GCM ciphertext+tag` over the root key.
    #[serde(with = "serde_bytes")]
    pub wrapped: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_cbor<T: Serialize>(value: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(value, &mut buf).expect("serialize");
        buf
    }

    fn from_cbor<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> T {
        ciborium::de::from_reader(bytes).expect("deserialize")
    }

    #[test]
    fn request_roundtrips() {
        let requests = [
            Request::Ping,
            Request::GetTxIoKeypair { epoch: 7 },
            Request::GetRngKeypair { epoch: 8 },
            Request::GetSnapshotKey { epoch: 9 },
            Request::WrapRootKey {
                root_key_request_binding: [0xAB; 32],
                peer_eph_pk: [0xCD; 33],
            },
        ];
        for request in requests {
            let decoded: Request = from_cbor(&to_cbor(&request));
            assert_eq!(format!("{request:?}"), format!("{decoded:?}"));
        }
    }

    #[test]
    fn response_roundtrips() {
        let response = Response::TxIoKeypair(TxIoKeypairBytes {
            sk: [1; 32],
            pk: [2; 33],
        });
        let Response::TxIoKeypair(keys) = from_cbor(&to_cbor(&response)) else {
            panic!("wrong variant");
        };
        assert_eq!(keys.sk, [1; 32]);
        assert_eq!(keys.pk, [2; 33]);

        let response = Response::SnapshotKey(SnapshotKeyBytes { key: [3; 32] });
        let Response::SnapshotKey(snapshot) = from_cbor(&to_cbor(&response)) else {
            panic!("wrong variant");
        };
        assert_eq!(snapshot.key, [3; 32]);

        let response = Response::RngKeypair(RngKeypairBytes {
            keypair: vec![4; 96],
        });
        let Response::RngKeypair(rng) = from_cbor(&to_cbor(&response)) else {
            panic!("wrong variant");
        };
        assert_eq!(rng.keypair, vec![4; 96]);

        // The two failure variants must stay distinct across the wire.
        let response = Response::Denied {
            message: "not authorized".into(),
        };
        let Response::Denied { message } = from_cbor(&to_cbor(&response)) else {
            panic!("wrong variant");
        };
        assert_eq!(message, "not authorized");
    }

    // The reason this crate exists over plain JSON: key material must encode
    // as CBOR byte strings (major type 2), not arrays of integers. 0x58 0x20
    // is "byte string, length 32".
    #[test]
    fn byte_fields_encode_as_cbor_byte_strings() {
        let encoded = to_cbor(&Request::WrapRootKey {
            root_key_request_binding: [0xAB; 32],
            peer_eph_pk: [0xCD; 33],
        });
        let marker = [0x58, 0x20, 0xAB, 0xAB];
        assert!(
            encoded.windows(marker.len()).any(|w| w == marker),
            "expected 32-byte byte-string header in {encoded:02x?}"
        );
    }

    #[test]
    fn secret_payload_debug_redacts_secrets() {
        let tx_io = TxIoKeypairBytes {
            sk: [1; 32],
            pk: [2; 33],
        };
        let debug = format!("{tx_io:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("1, 1"), "sk leaked: {debug}");

        let rng = RngKeypairBytes {
            keypair: vec![4; 96],
        };
        assert!(format!("{rng:?}").contains("<redacted>"));

        let snapshot = SnapshotKeyBytes { key: [3; 32] };
        assert!(format!("{snapshot:?}").contains("<redacted>"));
    }
}
