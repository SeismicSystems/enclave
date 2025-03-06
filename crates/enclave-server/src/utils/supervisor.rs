use std::process::{Command, Output};

const SEISMIC_RETH_SERVICE: &str = "reth";

fn supervisorctl_command(action: &str, service: &str) -> Result<Output, anyhow::Error> {
    let output: Output = Command::new("sudo")
        .arg("supervisorctl")
        .arg(action)
        .arg(service)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to execute supervisorctl command: {:?}", e))?;

    Ok(output)
}

pub fn stop_reth() -> Result<(), anyhow::Error> {
    supervisorctl_command("stop", SEISMIC_RETH_SERVICE)?;
    Ok(())
}

pub fn start_reth() -> Result<(), anyhow::Error> {
    supervisorctl_command("start", SEISMIC_RETH_SERVICE)?;
    Ok(())
}

pub fn reth_is_running() -> bool {
    let output = supervisorctl_command("status", SEISMIC_RETH_SERVICE).unwrap();
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|_| "Failed to parse command output".to_string())
        .unwrap();
    stdout.contains("RUNNING")
}
