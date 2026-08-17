use tracing::info;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

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
}
