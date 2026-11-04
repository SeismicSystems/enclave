//! Message types for the custodian socket.
//!
//! Everything crosses the wire as raw bytes — fixed-size arrays for keys and
//! digests, `Vec<u8>` for variable-length blobs — tagged `serde_bytes` so CBOR
//! encodes them as native byte strings. Callers convert to typed keys
//! (`secp256k1`, `aes-gcm`, `seismic_crypto::RngIkm`) at their own boundary;
//! see the crate-level boundary rule.
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
    /// Derive this epoch's tx-io ECDH secret key (TxSeismic calldata
    /// encryption); the caller derives the public key from it. Epochs are
    /// fixed at 0 until a consensus-driven manual rotation exists; same for
    /// the other purposes below.
    GetTxIoSecretKey { epoch: u64 },
    /// Derive only the public half of this epoch's tx-io key. The
    /// attestation service uses this to mint tx-io evidence without gaining
    /// access to `tx_io_sk`.
    GetTxIoPublicKey { epoch: u64 },
    /// Derive this epoch's RNG-precompile input key material.
    GetRngIkm { epoch: u64 },
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
        /// Which policy admitted the peer. The custodian wraps for
        /// [`AdmittedOn::FoundingPolicy`] only while it honors the founding
        /// policy, and answers [`Response::FoundingPolicyRetired`] otherwise.
        admitted_on: AdmittedOn,
    },
    /// Retire this custodian's founding policy for the rest of its root key's
    /// lifetime: from here on it refuses every founding-policy wrap. Only
    /// the custodian that minted the root key starts out honoring it; retiring
    /// is one-way and idempotent.
    RetireFoundingPolicy,
    /// Install a root key from a verified bootstrap response.
    ///
    /// Verify the responder's evidence and response transcript before calling
    /// this method. Raw evidence deliberately does not cross this boundary;
    /// possession of the ACL grant is the authorization assertion.
    InstallRootKeyFromVerifiedBootstrapResponse {
        /// Returned by the initial [`Request::CreateRootKeyBootstrapAttempt`]
        /// call. It selects the requester ephemeral secret retained for this
        /// bootstrap exchange.
        attempt_id: AttemptId,
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

/// Which policy admitted the peer a [`Request::WrapRootKey`] is for, and so
/// whether the custodian has the final say on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmittedOn {
    /// The founding policy: the founding accepted set, read at block 0 with no
    /// freshness check possible. Only the custodian that minted `root_key`
    /// wraps on it, and only until the chain has been seen past block 0.
    FoundingPolicy,
    /// The live policy, read at a fresh finalized block. Final.
    LivePolicy,
}

impl Request {
    /// Stable method label for ACL decisions and log lines.
    pub fn method(&self) -> &'static str {
        match self {
            Request::Ping => "ping",
            Request::GetTxIoSecretKey { .. } => "get_tx_io_secret_key",
            Request::GetTxIoPublicKey { .. } => "get_tx_io_public_key",
            Request::GetRngIkm { .. } => "get_rng_ikm",
            Request::GetSnapshotKey { .. } => "get_snapshot_key",
            Request::CreateRootKeyBootstrapAttempt => "create_root_key_bootstrap_attempt",
            Request::WrapRootKey { .. } => "wrap_root_key",
            Request::RetireFoundingPolicy => "retire_founding_policy",
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
    TxIoSecretKey(TxIoSecretKeyBytes),
    TxIoPublicKey(TxIoPublicKeyBytes),
    RngIkm(RngIkmBytes),
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
    /// The founding policy is retired: the answer to
    /// [`Request::RetireFoundingPolicy`], and the refusal of a
    /// [`Request::WrapRootKey`] for a peer admitted on the founding policy.
    FoundingPolicyRetired,
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
            Response::TxIoSecretKey(_) => "tx_io_secret_key",
            Response::TxIoPublicKey(_) => "tx_io_public_key",
            Response::RngIkm(_) => "rng_ikm",
            Response::SnapshotKey(_) => "snapshot_key",
            Response::RootKeyBootstrapAttemptCreated(_) => "root_key_bootstrap_attempt_created",
            Response::WrappedRootKey(_) => "wrapped_root_key",
            Response::RootKeyInstalled => "root_key_installed",
            Response::RootKeyAlreadyPresent => "root_key_already_present",
            Response::RootKeyAbsent => "root_key_absent",
            Response::FoundingPolicyRetired => "founding_policy_retired",
            Response::Denied { .. } => "denied",
            Response::Error { .. } => "error",
        }
    }
}

/// secp256k1 tx-io secret key as raw bytes. Zeroized on drop.
///
/// Only the secret half crosses the wire: the caller derives the public key
/// from it, so a mismatched pair is unrepresentable.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct TxIoSecretKeyBytes {
    #[serde(with = "serde_bytes")]
    pub sk: [u8; 32],
}

// Manual Debug so a stray `{:?}` on a response can't log the secret.
impl fmt::Debug for TxIoSecretKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxIoSecretKeyBytes")
            .field("sk", &"<redacted>")
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

/// Opaque correlation token for one requester-side root-key bootstrap attempt.
///
/// The custodian mints it on [`Request::CreateRootKeyBootstrapAttempt`] and
/// takes it back on [`Request::InstallRootKeyFromVerifiedBootstrapResponse`],
/// where it selects the retained ephemeral secret. Callers pass it through
/// without inspecting it. Its own type keeps it from being swapped with the
/// request binding, the other 32-byte argument of the install call.
///
/// Encodes as a bare CBOR byte string, like the raw array it wraps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AttemptId(#[serde(with = "serde_bytes")] pub [u8; 32]);

/// One pending requester-side root-key bootstrap attempt. The matching
/// ephemeral secret remains in the custodian process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootKeyBootstrapAttemptBytes {
    /// Selects the retained ephemeral secret on install.
    pub attempt_id: AttemptId,
    /// Requester ephemeral ECDH public key, 33-byte compressed SEC1.
    #[serde(with = "serde_bytes")]
    pub requester_eph_pk: [u8; 33],
}

/// HKDF input key material for the RNG precompile, 64 opaque bytes. Callers
/// convert to and from `seismic_crypto::RngIkm` at their boundary. Zeroized on
/// drop.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RngIkmBytes {
    #[serde(with = "serde_bytes")]
    pub ikm: [u8; 64],
}

impl fmt::Debug for RngIkmBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RngIkmBytes")
            .field("ikm", &"<redacted>")
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

/// One wrap operation's output — `WrappedRootKey` from seismic-custodian
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
            Request::GetTxIoSecretKey { epoch: 7 },
            Request::GetTxIoPublicKey { epoch: 7 },
            Request::GetRngIkm { epoch: 8 },
            Request::GetSnapshotKey { epoch: 9 },
            Request::CreateRootKeyBootstrapAttempt,
            Request::WrapRootKey {
                root_key_request_binding: [0xAB; 32],
                peer_eph_pk: [0xCD; 33],
                admitted_on: AdmittedOn::FoundingPolicy,
            },
            Request::RetireFoundingPolicy,
            Request::InstallRootKeyFromVerifiedBootstrapResponse {
                attempt_id: AttemptId([0x11; 32]),
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
        let response = Response::TxIoSecretKey(TxIoSecretKeyBytes { sk: [1; 32] });
        let Response::TxIoSecretKey(keys) = from_cbor(&to_cbor(&response)) else {
            panic!("wrong variant");
        };
        assert_eq!(keys.sk, [1; 32]);

        let response = Response::SnapshotKey(SnapshotKeyBytes { key: [3; 32] });
        let Response::SnapshotKey(snapshot) = from_cbor(&to_cbor(&response)) else {
            panic!("wrong variant");
        };
        assert_eq!(snapshot.key, [3; 32]);

        let response = Response::RngIkm(RngIkmBytes { ikm: [4; 64] });
        let Response::RngIkm(rng) = from_cbor(&to_cbor(&response)) else {
            panic!("wrong variant");
        };
        assert_eq!(rng.ikm, [4; 64]);

        let response = Response::TxIoPublicKey(TxIoPublicKeyBytes { pk: [5; 33] });
        let Response::TxIoPublicKey(tx_io) = from_cbor(&to_cbor(&response)) else {
            panic!("wrong variant");
        };
        assert_eq!(tx_io.pk, [5; 33]);

        let response = Response::RootKeyBootstrapAttemptCreated(RootKeyBootstrapAttemptBytes {
            attempt_id: AttemptId([6; 32]),
            requester_eph_pk: [7; 33],
        });
        let Response::RootKeyBootstrapAttemptCreated(attempt) = from_cbor(&to_cbor(&response))
        else {
            panic!("wrong variant");
        };
        assert_eq!(attempt.attempt_id, AttemptId([6; 32]));
        assert_eq!(attempt.requester_eph_pk, [7; 33]);

        for response in [
            Response::RootKeyInstalled,
            Response::RootKeyAlreadyPresent,
            Response::RootKeyAbsent,
            Response::FoundingPolicyRetired,
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
            admitted_on: AdmittedOn::LivePolicy,
        });
        let marker = [0x58, 0x20, 0xAB, 0xAB];
        assert!(
            encoded.windows(marker.len()).any(|w| w == marker),
            "expected 32-byte byte-string header in {encoded:02x?}"
        );

        // The newtype must not change the wire format: still a bare byte
        // string, not an array or a one-field map.
        let encoded = to_cbor(&RootKeyBootstrapAttemptBytes {
            attempt_id: AttemptId([0x5A; 32]),
            requester_eph_pk: [0xCD; 33],
        });
        let marker = [0x58, 0x20, 0x5A, 0x5A];
        assert!(
            encoded.windows(marker.len()).any(|w| w == marker),
            "expected 32-byte byte-string header in {encoded:02x?}"
        );
    }

    #[test]
    fn response_kind_is_payload_free() {
        let response = Response::TxIoSecretKey(TxIoSecretKeyBytes { sk: [0xA5; 32] });
        assert_eq!(response.kind(), "tx_io_secret_key");
        assert!(!response.kind().contains("a5"));

        let response = Response::Error {
            message: "private implementation detail".into(),
        };
        assert_eq!(response.kind(), "error");
        assert!(!response.kind().contains("private"));
    }

    #[test]
    fn secret_payload_debug_redacts_secrets() {
        let tx_io = TxIoSecretKeyBytes { sk: [1; 32] };
        let debug = format!("{tx_io:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("1, 1"), "sk leaked: {debug}");

        let rng = RngIkmBytes { ikm: [4; 64] };
        assert!(format!("{rng:?}").contains("<redacted>"));

        let snapshot = SnapshotKeyBytes { key: [3; 32] };
        assert!(format!("{snapshot:?}").contains("<redacted>"));
    }
}
