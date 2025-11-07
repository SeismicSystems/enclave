use jsonrpsee::types::{ErrorCode, ErrorObjectOwned};
use libc::uid_t;
use std::process::{Command, Output};

const SEISMIC_RETH_SERVICE: &str = "reth";

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

/// Executes a `service` command for managing services.
///
/// # Arguments
/// * `action` - The action to perform (e.g., "start", "stop", "status").
/// * `service` - The name of the service to manage, e.g. "reth".
///
/// # Returns
/// * `Result<Output, anyhow::Error>` - The command output or an error.
fn service_command(action: &str, service: &str) -> Result<Output, anyhow::Error> {
    let output = Command::new("service").arg(service).arg(action).output()?;

    Ok(output)
}

/// Stops the `reth` service using `service`.
pub fn stop_reth() -> Result<(), anyhow::Error> {
    service_command("stop", SEISMIC_RETH_SERVICE)
        .map_err(|e| anyhow::anyhow!("service stop reth failed: {}", e))?;
    Ok(())
}

/// Starts the `reth` service using `service`.
pub fn start_reth() -> Result<(), anyhow::Error> {
    service_command("start", SEISMIC_RETH_SERVICE)
        .map_err(|e| anyhow::anyhow!("service start reth failed: {}", e))?;
    Ok(())
}

/// Checks if the `reth` service is running using `service status`.
///
/// # Returns
/// * `bool` - `true` if the service is running, otherwise `false`.
pub fn reth_is_running() -> bool {
    let output = service_command("status", SEISMIC_RETH_SERVICE);

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.contains("running") || stdout.contains("is running")
    } else {
        false
    }
}
