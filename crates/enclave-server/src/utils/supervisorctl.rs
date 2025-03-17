use std::process::{Command, Output};

const SEISMIC_RETH_SERVICE: &str = "reth";

/// Executes a `supervisorctl` command for managing services.
///
/// # Arguments
/// * `action` - The action to perform (e.g., "start", "stop", "status").
/// * `service` - The name of the service to manage, e.g. "reth".
///
/// # Returns
/// * `Result<Output, anyhow::Error>` - The command output or an error for internal failures.
///    The output may contain additional information about the command's execution, ex stderr
///    if the command exited with an error.
fn supervisorctl_command(action: &str, service: &str) -> Result<Output, anyhow::Error> {
    let output: Output = Command::new("sudo")
        .arg("supervisorctl")
        .arg(action)
        .arg(service)
        .output()?;

    Ok(output)
}

/// Stops the `reth` service using `supervisorctl`.
pub fn stop_reth() -> Result<(), anyhow::Error> {
    supervisorctl_command("stop", SEISMIC_RETH_SERVICE)
        .map_err(|e| anyhow::anyhow!("supervisorctl stop reth failed: {}", e))?;
    Ok(())
}

/// Starts the `reth` service using `supervisorctl`.
pub fn start_reth() -> Result<(), anyhow::Error> {
    supervisorctl_command("start", SEISMIC_RETH_SERVICE)
        .map_err(|e| anyhow::anyhow!("supervisorctl start reth failed: {}", e))?;
    Ok(())
}

/// Checks if the `reth` service is running.
///
/// # Returns
/// * `bool` - `true` if the service is running, otherwise `false`.
pub fn reth_is_running() -> bool {
    let output = supervisorctl_command("status", SEISMIC_RETH_SERVICE)
        .map_err(|e| anyhow::anyhow!("supervisorctl status reth failed: {}", e))
        .unwrap();
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|_| "Failed to parse command output".to_string())
        .unwrap();
    stdout.contains("RUNNING")
}
