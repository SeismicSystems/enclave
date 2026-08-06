use crate::framing::MAX_FRAME_BODY_LEN;

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("frame body length {len} exceeds maximum {MAX_FRAME_BODY_LEN}")]
    FrameTooLarge { len: usize },
    #[error("CBOR encode: {0}")]
    Encode(String),
    #[error("CBOR decode: {0}")]
    Decode(String),
    /// The transport's ACL refused this method ([`crate::Response::Denied`]);
    /// retrying cannot succeed until the node's ACL changes.
    #[error("custodian denied: {0}")]
    Denied(String),
    /// The custodian accepted the request but the operation failed
    /// ([`crate::Response::Error`]).
    #[error("custodian: {0}")]
    Custodian(String),
    /// The custodian received a root-key-dependent request while no root key
    /// was present in its memory.
    #[error("custodian root key is absent")]
    RootKeyAbsent,
    /// The custodian holds no key for this epoch (centralized custodian:
    /// the council has not delivered it yet). Retriable.
    #[error("custodian holds no key for epoch {epoch}")]
    EpochKeyUnavailable { epoch: u64 },
    /// The custodian answered, but with a variant that doesn't match the
    /// request — a protocol bug on one side or the other.
    #[error("unexpected response variant to {method}: received {received}")]
    UnexpectedResponse {
        method: &'static str,
        /// Payload-free [`crate::Response::kind`] label; never key material.
        received: &'static str,
    },
}
