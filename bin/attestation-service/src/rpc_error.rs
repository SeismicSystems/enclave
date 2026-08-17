//! The service's JSON-RPC error contract.
//!
//! Four codes reach a caller, and a joining node in another process decides
//! what to do next from the code alone: whether its own evidence was refused,
//! or whether this responder simply could not answer. Every message is a
//! stable constant — an unauthenticated caller learns the outcome and nothing
//! about why — so the failure detail lives in this responder's log instead.

use crate::admission::{AdmissionDenial, DenialKind};
use jsonrpsee::types::{ErrorCode, ErrorObjectOwned};
use std::fmt::Debug;
use tracing::{error, warn};

/// Terminal verdict: the requester does not get the key, and retrying with
/// the same image cannot change the answer.
pub const ROOT_KEY_REQUEST_DENIED_CODE: i32 = -32001;
/// The responder could not decide, because its own chain or registry read
/// produced no usable answer. The requester's evidence is not what failed:
/// worth retrying — against another peer, or this responder later.
pub const ROOT_KEY_ADMISSION_UNAVAILABLE_CODE: i32 = -32002;

pub(crate) fn invalid_root_key_request_rpc_error(error: impl Debug) -> ErrorObjectOwned {
    warn!(?error, "invalid root-key request");
    ErrorObjectOwned::owned(
        ErrorCode::InvalidParams.code(),
        "Invalid root-key request",
        None::<()>,
    )
}

pub(crate) fn internal_rpc_error(operation: &'static str, error: impl Debug) -> ErrorObjectOwned {
    error!(?error, operation, "RPC operation failed");
    ErrorObjectOwned::owned(
        ErrorCode::InternalError.code(),
        "Internal error",
        None::<()>,
    )
}

pub(crate) fn root_key_request_denied_rpc_error(error: impl Debug) -> ErrorObjectOwned {
    warn!(?error, "root-key request denied");
    ErrorObjectOwned::owned(
        ROOT_KEY_REQUEST_DENIED_CODE,
        "Root-key request denied",
        None::<()>,
    )
}

pub(crate) fn root_key_admission_unavailable_rpc_error(error: impl Debug) -> ErrorObjectOwned {
    warn!(?error, "root-key admission temporarily unavailable");
    ErrorObjectOwned::owned(
        ROOT_KEY_ADMISSION_UNAVAILABLE_CODE,
        "Root-key admission temporarily unavailable",
        None::<()>,
    )
}

/// Route a failed root-key answer to its wire error, by what the failure says
/// about the two parties (see [`DenialKind`]). The two codes carry the two
/// moves open to a requester: change something about itself, or ask someone
/// else. Either way the message is a stable constant; failure detail stays in
/// the responder's log.
pub(crate) fn root_key_answer_rpc_error(error: anyhow::Error) -> ErrorObjectOwned {
    let kind = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<AdmissionDenial>())
        .map(AdmissionDenial::kind);
    match kind {
        Some(DenialKind::ResponderMisconfigured | DenialKind::ResponderTransient) => {
            root_key_admission_unavailable_rpc_error(error)
        }
        // A verdict on the requester, and every failure that carries no typed
        // denial — evidence verification among them, whatever its cause.
        // TODO: attribute evidence failures the way admission denials are.
        // Verification fetches collateral over the network, so a fetch this
        // responder could not complete is its own fault, yet it reaches the
        // requester here as a terminal verdict on evidence that was fine.
        Some(DenialKind::RequesterVerdict) | None => root_key_request_denied_rpc_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_errors_expose_only_stable_messages() {
        let invalid = invalid_root_key_request_rpc_error("private parser detail");
        assert_eq!(invalid.code(), ErrorCode::InvalidParams.code());
        assert_eq!(invalid.message(), "Invalid root-key request");

        let denied = root_key_request_denied_rpc_error("private verifier detail");
        assert_eq!(denied.code(), ROOT_KEY_REQUEST_DENIED_CODE);
        assert_eq!(denied.message(), "Root-key request denied");

        let unavailable = root_key_admission_unavailable_rpc_error("private chain detail");
        assert_eq!(unavailable.code(), ROOT_KEY_ADMISSION_UNAVAILABLE_CODE);
        assert_eq!(
            unavailable.message(),
            "Root-key admission temporarily unavailable"
        );

        let internal = internal_rpc_error("generating evidence", "private backend detail");
        assert_eq!(internal.code(), ErrorCode::InternalError.code());
        assert_eq!(internal.message(), "Internal error");

        for error in [invalid, denied, unavailable, internal] {
            assert!(!error.to_string().contains("private"));
        }
    }

    #[test]
    fn responder_faults_map_to_unavailable_others_to_denied() {
        use seismic_attestation::AttestationError;

        // The nesting a real handshake produces: the bootstrap wraps the
        // attestation error in anyhow context, which carries the typed
        // denial as a source.
        let handshake_error = |denial: AdmissionDenial| {
            anyhow::Error::new(AttestationError::AdmissionDenied(Box::new(denial)))
                .context("verifying requester attestation evidence")
        };

        let unavailable =
            root_key_answer_rpc_error(handshake_error(AdmissionDenial::ChainRegressedToGenesis));
        assert_eq!(unavailable.code(), ROOT_KEY_ADMISSION_UNAVAILABLE_CODE);

        // A responder on the wrong chain is unavailable rather than denying,
        // even though waiting cannot fix it: the requester's move is to ask
        // another peer, and its evidence is not what failed.
        let wrong_chain =
            root_key_answer_rpc_error(handshake_error(AdmissionDenial::ChainGenesisMismatch {
                expected: alloy_primitives::B256::repeat_byte(0xb0),
                found: alloy_primitives::B256::repeat_byte(0xef),
            }));
        assert_eq!(wrong_chain.code(), ROOT_KEY_ADMISSION_UNAVAILABLE_CODE);

        let verdict = root_key_answer_rpc_error(handshake_error(
            AdmissionDenial::RegistryNotAccepted(alloy_primitives::B256::ZERO.into()),
        ));
        assert_eq!(verdict.code(), ROOT_KEY_REQUEST_DENIED_CODE);

        // Failures with no admission denial in the chain (e.g. quote
        // verification) stay on the denied verdict.
        let other = root_key_answer_rpc_error(anyhow::anyhow!("quote verification failed"));
        assert_eq!(other.code(), ROOT_KEY_REQUEST_DENIED_CODE);
    }
}
