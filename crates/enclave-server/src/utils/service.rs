
use std::process::{Command, Output};

const SEISMIC_RETH_SERVICE: &str = "reth";

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
