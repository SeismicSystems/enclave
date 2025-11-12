use jsonrpsee::types::{ErrorCode, ErrorObjectOwned};
use libc::uid_t;
use tracing::info;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

pub fn get_current_uid() -> uid_t {
    unsafe { libc::getuid() }
}

pub fn anyhow_to_rpc_error(e: anyhow::Error) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(ErrorCode::InternalError.code(), e.to_string(), None::<()>)
}

/// Checks if the current user has root (sudo) privileges.
///
/// This function runs the `id -u` command, which returns the current user's ID.
/// In Unix-like systems, the user ID of the root user is `0`. The function checks
/// if the output of the `id -u` command is `"0"`, indicating that the user is running
/// as root (with sudo privileges).
///
/// # Returns
///
/// - `true`: If the user has root privileges (user ID is `0`).
/// - `false`: If the user does not have root privileges.
pub fn is_sudo() -> bool {
    use std::process::Command;

    // Run the "id -u" command to check the user ID
    let output = Command::new("id")
        .arg("-u")
        .output()
        .expect("Failed to execute id command");

    // Convert the output to a string and trim any whitespace
    let user_id = String::from_utf8(output.stdout).unwrap().trim().to_string();

    // Check if the user ID is 0 (which means the user is root)
    user_id == "0"
}

pub fn init_tracing() {
    // Read log level from RUST_LOG
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));

    // Initialize the subscriber
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter) // Use dynamic log level
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    info!("Enclave server tracing initialized");
}
