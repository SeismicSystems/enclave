use crate::admission::AdmissionDenial;
use jsonrpsee::types::{ErrorCode, ErrorObjectOwned};
use std::fmt::Debug;
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

/// Terminal verdict: the requester does not get the key, and retrying with
/// the same image cannot change the answer.
const ROOT_KEY_REQUEST_DENIED_CODE: i32 = -32001;
/// Transient failure: the responder could not decide, because its own chain
/// or registry read produced no usable answer. Worth retrying — against this
/// responder moments later, or against another peer.
const ROOT_KEY_ADMISSION_UNAVAILABLE_CODE: i32 = -32002;

pub(crate) fn invalid_root_key_request_rpc_error(error: impl Debug) -> ErrorObjectOwned {
    warn!(?error, "invalid root-key request");
    ErrorObjectOwned::owned(
        ErrorCode::InvalidParams.code(),
        "Invalid root-key request",
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

/// Route a failed root-key answer to its wire error. An [`AdmissionDenial`]
/// that is transient (see [`AdmissionDenial::is_transient`]) maps to
/// [`ROOT_KEY_ADMISSION_UNAVAILABLE_CODE`]; everything else — admission
/// verdicts, and failures carrying no typed denial (e.g. quote verification)
/// — maps to [`ROOT_KEY_REQUEST_DENIED_CODE`]. Either way the message is a
/// stable constant; failure detail stays in the responder's log.
pub(crate) fn root_key_answer_rpc_error(error: anyhow::Error) -> ErrorObjectOwned {
    let transient = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<AdmissionDenial>())
        .is_some_and(AdmissionDenial::is_transient);
    if transient {
        root_key_admission_unavailable_rpc_error(error)
    } else {
        root_key_request_denied_rpc_error(error)
    }
}

pub(crate) fn internal_rpc_error(operation: &'static str, error: impl Debug) -> ErrorObjectOwned {
    error!(?error, operation, "RPC operation failed");
    ErrorObjectOwned::owned(
        ErrorCode::InternalError.code(),
        "Internal error",
        None::<()>,
    )
}

/// Checks if the current user has root (sudo) privileges by running `id -u`
/// and comparing the result to `0` (root).
///
/// # Returns
///
/// - `true`: user is root.
/// - `false`: user is not root.
pub fn is_sudo() -> bool {
    let output = std::process::Command::new("id")
        .arg("-u")
        .output()
        .expect("Failed to execute id command");

    let user_id = String::from_utf8(output.stdout).unwrap().trim().to_string();
    user_id == "0"
}

pub fn init_tracing() {
    // Read log level from RUST_LOG, default to "info" if unset — the same
    // default as the custodian service and the production unit files.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = FmtSubscriber::builder().with_env_filter(filter).finish();

    // Keep the first subscriber on repeat calls: every integration test in
    // the shared test process initializes tracing.
    if tracing::subscriber::set_global_default(subscriber).is_ok() {
        info!("Attestation service tracing initialized");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every integration test in one process initializes tracing; a repeat
    // call must keep the first subscriber rather than panic.
    #[test]
    fn init_tracing_is_idempotent() {
        init_tracing();
        init_tracing();
    }

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
    fn transient_admission_failures_map_to_unavailable_others_to_denied() {
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
