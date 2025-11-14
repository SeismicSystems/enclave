use crate::error::{Result, TdxInitError};
use tokio::process::Command;
use tracing::info;

pub async fn execute_command(cmd: &str, args: &[&str]) -> Result<()> {
    info!("Executing: {} {}", cmd, args.join(" "));

    let output = Command::new(cmd).args(args).output().await?;

    if !output.status.success() {
        return Err(TdxInitError::CommandError {
            cmd: format!("{} {}", cmd, args.join(" ")),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    Ok(())
}

pub async fn execute_command_with_stdin(cmd: &str, args: &[&str], stdin_data: &str) -> Result<()> {
    info!("Executing: {} {} (with stdin)", cmd, args.join(" "));

    let mut child = Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(stdin_data.as_bytes()).await?;
        drop(stdin);
    }

    let output = child.wait_with_output().await?;

    if !output.status.success() {
        return Err(TdxInitError::CommandError {
            cmd: format!("{} {}", cmd, args.join(" ")),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    Ok(())
}

pub async fn execute_command_with_output(cmd: &str, args: &[&str]) -> Result<Vec<u8>> {
    info!("Executing: {} {}", cmd, args.join(" "));

    let output = Command::new(cmd).args(args).output().await?;

    if !output.status.success() {
        return Err(TdxInitError::CommandError {
            cmd: format!("{} {}", cmd, args.join(" ")),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    Ok(output.stdout)
}
