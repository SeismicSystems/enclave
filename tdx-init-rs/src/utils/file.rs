use crate::error::Result;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::fs;
use tracing::warn;

pub async fn write_file_with_perms<P: AsRef<Path>>(
    path: P,
    content: &str,
    mode: u32,
) -> Result<()> {
    fs::write(&path, content).await?;
    set_file_permissions(&path, mode).await?;
    Ok(())
}

pub async fn set_file_permissions<P: AsRef<Path>>(path: P, mode: u32) -> Result<()> {
    let mut perms = fs::metadata(&path).await?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(&path, perms).await?;
    Ok(())
}

pub async fn create_dir_safe<P: AsRef<Path>>(path: P) -> bool {
    match fs::create_dir_all(&path).await {
        Ok(()) => true,
        Err(e) => {
            warn!(
                "Warning: Could not create directory {:?}: {}",
                path.as_ref(),
                e,
            );
            false
        }
    }
}
