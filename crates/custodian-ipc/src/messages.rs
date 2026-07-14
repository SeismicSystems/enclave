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

    // ==================== Purpose-key access ====================
    /// Derive this epoch's tx-io ECDH keypair (TxSeismic calldata
    /// encryption). Epochs are fixed at 0 until a consensus-driven manual
    /// rotation exists; same for the other purposes below.
    GetTxIoKeypair { epoch: u64 },
    /// Derive only the public half of this epoch's tx-io key. The
    /// attestation service uses this to mint tx-io evidence without gaining
    /// access to `tx_io_sk`.
    GetTxIoPublicKey { epoch: u64 },
    /// Derive this epoch's RNG-precompile keypair.
    GetRngKeypair { epoch: u64 },
    /// Derive this epoch's snapshot encryption key.
    GetSnapshotKey { epoch: u64 },

    // ==================== Root-key bootstrap ====================
    /// Start requester-side bootstrap without exposing the requester's
    /// ephemeral ECDH secret to the network-facing attestation service.
    ///
    /// At most one attempt is retained. Starting another attempt invalidates
    /// and drops the previous one.
    CreateRootKeyBootstrapAttempt,
    /// AEAD-wrap the root key for an attestation-verified peer.
    ///
    /// Verify the bootstrap requester before calling this method: recompute
    /// its expected request binding from the local network ID, requester nonce,
    /// and requester ephemeral public key, then verify its evidence against
    /// that binding. Calling this method authorizes release of the wrapped root
    /// key, so the ACL must confine it to the attestation service.
    WrapRootKey {
        /// SHA-256 binding of the original bootstrap request transcript:
        /// `root_key_request_binding(network_id, nonce_b, eph_pk_b)`. The
        /// custodian carries it opaquely into the root-key ciphertext as AEAD
        /// AAD.
        #[serde(with = "serde_bytes")]
        root_key_request_binding: [u8; 32],
        /// Peer's ephemeral ECDH public key, 33-byte compressed SEC1.
        #[serde(with = "serde_bytes")]
        peer_eph_pk: [u8; 33],
    },
    /// Install a root key from a verified bootstrap response.
    ///
    /// Verify the responder's evidence and response transcript before calling
    /// this method. Raw evidence deliberately does not cross this boundary;
    /// possession of the ACL grant is the authorization assertion.
    InstallRootKeyFromVerifiedBootstrapResponse {
        /// Opaque attempt identifier returned by the initial
        /// [`Request::CreateRootKeyBootstrapAttempt`] call. It selects the
        /// requester ephemeral secret retained for this bootstrap exchange.
        #[serde(with = "serde_bytes")]
        attempt_id: [u8; 32],
        /// SHA-256 binding of the original bootstrap request transcript:
        /// `root_key_request_binding(network_id, nonce_b, eph_pk_b)`. This must
        /// be the same value supplied to [`Request::WrapRootKey`] by the
        /// responder; the custodian uses it as AEAD AAD when unwrapping.
        #[serde(with = "serde_bytes")]
        root_key_request_binding: [u8; 32],
        /// Responder ephemeral ECDH public key, 33-byte compressed SEC1.
        #[serde(with = "serde_bytes")]
        responder_eph_pk: [u8; 33],
        /// `nonce(12) || AES-256-GCM ciphertext+tag` over the root key.
        #[serde(with = "serde_bytes")]
        wrapped_root_key: Vec<u8>,
    },
}

impl Request {
    /// Stable method label for ACL decisions and log lines.
    pub fn method(&self) -> &'static str {
        match self {
            Request::Ping => "ping",
            Request::GetTxIoKeypair { .. } => "get_tx_io_keypair",
            Request::GetTxIoPublicKey { .. } => "get_tx_io_public_key",
            Request::GetRngKeypair { .. } => "get_rng_keypair",
            Request::GetSnapshotKey { .. } => "get_snapshot_key",
            Request::CreateRootKeyBootstrapAttempt => "create_root_key_bootstrap_attempt",
            Request::WrapRootKey { .. } => "wrap_root_key",
            Request::InstallRootKeyFromVerifiedBootstrapResponse { .. } => {
                "install_root_key_from_verified_bootstrap_response"
            }
        }
    }
}

/// One response over the custodian socket. Method-specific results are joined
/// by explicit root-key state outcomes plus two failures split by layer:
/// [`Response::Denied`] is minted only by the transport's ACL loop, while
/// [`Response::Error`] is minted only by the host's dispatch handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Pong,
    TxIoKeypair(TxIoKeypairBytes),
    TxIoPublicKey(TxIoPublicKeyBytes),
    RngKeypair(RngKeypairBytes),
    SnapshotKey(SnapshotKeyBytes),
    RootKeyBootstrapAttemptCreated(RootKeyBootstrapAttemptBytes),
    WrappedRootKey(WrappedRootKeyBytes),
    RootKeyInstalled,
    /// A create/install request arrived while the root key was already
    /// present. Kept distinct from an internal error so a restarted
    /// attestation service can proceed without a state-query RPC.
    RootKeyAlreadyPresent,
    /// The requested derivation/wrap needs `root_key`, but none is present in
    /// the custodian's memory.
    RootKeyAbsent,
    /// The ACL refused this peer the method; the handler never saw the
    /// request. Retrying cannot succeed until the node's ACL changes.
    Denied {
        message: String,
    },
    /// The handler accepted the request but the operation failed (bad
    /// argument or internal error); no partial output is returned. Hosts must
    /// put only stable, sanitized text here; detailed errors stay in their
    /// local logs.
    Error {
        message: String,
    },
}

impl Response {
    /// Stable, payload-free variant label for protocol diagnostics. This is
    /// safe to include in client errors even when the response variant carries
    /// secret key material.
    pub fn kind(&self) -> &'static str {
        match self {
            Response::Pong => "pong",
            Response::TxIoKeypair(_) => "tx_io_keypair",
            Response::TxIoPublicKey(_) => "tx_io_public_key",
            Response::RngKeypair(_) => "rng_keypair",
            Response::SnapshotKey(_) => "snapshot_key",
            Response::RootKeyBootstrapAttemptCreated(_) => "root_key_bootstrap_attempt_created",
            Response::WrappedRootKey(_) => "wrapped_root_key",
            Response::RootKeyInstalled => "root_key_installed",
            Response::RootKeyAlreadyPresent => "root_key_already_present",
            Response::RootKeyAbsent => "root_key_absent",
            Response::Denied { .. } => "denied",
            Response::Error { .. } => "error",
        }
    }
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

/// Public half of a tx-io keypair, returned to the attestation service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxIoPublicKeyBytes {
    /// 33-byte compressed SEC1 public key.
    #[serde(with = "serde_bytes")]
    pub pk: [u8; 33],
}

/// One pending requester-side root-key bootstrap attempt. The matching
/// ephemeral secret remains in the custodian process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootKeyBootstrapAttemptBytes {
    /// Opaque correlation token used to select the retained ephemeral secret.
    #[serde(with = "serde_bytes")]
    pub attempt_id: [u8; 32],
    /// Requester ephemeral ECDH public key, 33-byte compressed SEC1.
    #[serde(with = "serde_bytes")]
    pub requester_eph_pk: [u8; 33],
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
            Request::GetTxIoPublicKey { epoch: 7 },
            Request::GetRngKeypair { epoch: 8 },
            Request::GetSnapshotKey { epoch: 9 },
            Request::CreateRootKeyBootstrapAttempt,
            Request::WrapRootKey {
                root_key_request_binding: [0xAB; 32],
                peer_eph_pk: [0xCD; 33],
            },
            Request::InstallRootKeyFromVerifiedBootstrapResponse {
                attempt_id: [0x11; 32],
                root_key_request_binding: [0xAB; 32],
                responder_eph_pk: [0xCD; 33],
                wrapped_root_key: vec![0xEF; 60],
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

        let response = Response::TxIoPublicKey(TxIoPublicKeyBytes { pk: [5; 33] });
        let Response::TxIoPublicKey(tx_io) = from_cbor(&to_cbor(&response)) else {
            panic!("wrong variant");
        };
        assert_eq!(tx_io.pk, [5; 33]);

        let response = Response::RootKeyBootstrapAttemptCreated(RootKeyBootstrapAttemptBytes {
            attempt_id: [6; 32],
            requester_eph_pk: [7; 33],
        });
        let Response::RootKeyBootstrapAttemptCreated(attempt) = from_cbor(&to_cbor(&response))
        else {
            panic!("wrong variant");
        };
        assert_eq!(attempt.attempt_id, [6; 32]);
        assert_eq!(attempt.requester_eph_pk, [7; 33]);

        for response in [
            Response::RootKeyInstalled,
            Response::RootKeyAlreadyPresent,
            Response::RootKeyAbsent,
        ] {
            let expected_kind = response.kind();
            let decoded: Response = from_cbor(&to_cbor(&response));
            assert_eq!(decoded.kind(), expected_kind);
        }

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
    fn response_kind_is_payload_free() {
        let response = Response::TxIoKeypair(TxIoKeypairBytes {
            sk: [0xA5; 32],
            pk: [2; 33],
        });
        assert_eq!(response.kind(), "tx_io_keypair");
        assert!(!response.kind().contains("a5"));

        let response = Response::Error {
            message: "private implementation detail".into(),
        };
        assert_eq!(response.kind(), "error");
        assert!(!response.kind().contains("private"));
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
