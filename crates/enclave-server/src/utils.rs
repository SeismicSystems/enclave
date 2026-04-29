use jsonrpsee::types::{ErrorCode, ErrorObjectOwned};
use tracing::info;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

pub fn anyhow_to_rpc_error(e: anyhow::Error) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(ErrorCode::InternalError.code(), e.to_string(), None::<()>)
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
