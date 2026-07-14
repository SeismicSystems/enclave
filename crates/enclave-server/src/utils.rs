use jsonrpsee::types::{ErrorCode, ErrorObjectOwned};
use std::fmt::Debug;
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

const ROOT_KEY_REQUEST_DENIED_CODE: i32 = -32001;

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
    // Read log level from RUST_LOG, default to "debug" if unset.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));

    let subscriber = FmtSubscriber::builder().with_env_filter(filter).finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    info!("Enclave server tracing initialized");
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

        let internal = internal_rpc_error("generating evidence", "private backend detail");
        assert_eq!(internal.code(), ErrorCode::InternalError.code());
        assert_eq!(internal.message(), "Internal error");

        for error in [invalid, denied, internal] {
            assert!(!error.to_string().contains("private"));
        }
    }
}
