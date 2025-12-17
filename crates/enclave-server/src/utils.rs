use anyhow::{Result, anyhow};
use jsonrpsee::types::{ErrorCode, ErrorObjectOwned};
use libc::uid_t;
use std::{
    fs::{self, File},
    io::{Read as _, Write as _},
    path::Path,
    process::Command,
};
use tracing::info;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
#[cfg(feature = "systemctl")]
pub const RETH_CONTROL_CMD: &str = "/usr/bin/systemctl";

#[cfg(not(feature = "systemctl"))]
pub const RETH_CONTROL_CMD: &str = "supervisorctl";

const SEISMIC_RETH_SERVICE: &str = "reth";
const SEISMIC_SUMMIT_SERVICE: &str = "summit";

pub fn get_current_uid() -> uid_t {
    unsafe { libc::getuid() }
}

pub fn anyhow_to_rpc_error(e: anyhow::Error) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(ErrorCode::InternalError.code(), e.to_string(), None::<()>)
}

pub fn string_to_rpc_error(e: String) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(ErrorCode::InternalError.code(), e, None::<()>)
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

//reads the first n bytes of a file
// useful for checking file equality
pub fn read_first_n_bytes(file_path: &str, n: usize) -> Result<Vec<u8>, anyhow::Error> {
    let mut file = File::open(file_path)?;
    let mut buffer = vec![0; n]; // Allocate a buffer of size `n`
    let bytes_read = file.read(&mut buffer)?;

    buffer.truncate(bytes_read); // Truncate buffer in case file is smaller than `n`
    Ok(buffer)
}

// Function to generate a dummy database file
pub fn generate_dummy_file(path: &Path, size: usize) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(&vec![0u8; size])?; // Fill with zero bytes
    Ok(())
}

pub async fn start_reth() -> Result<()> {
    let mut child = Command::new(RETH_CONTROL_CMD)
        .arg("start")
        .arg(SEISMIC_RETH_SERVICE)
        .spawn()
        .unwrap();

    let status = child.wait().unwrap();

    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("Failed to start reth"))
    }
}

pub async fn stop_reth() -> Result<()> {
    info!("Stopping reth with: {RETH_CONTROL_CMD} stop {SEISMIC_RETH_SERVICE}");
    let mut child = Command::new(RETH_CONTROL_CMD)
        .arg("stop")
        .arg(SEISMIC_RETH_SERVICE)
        .spawn()
        .unwrap();

    let status = child.wait().unwrap();

    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("Failed to stop reth"))
    }
}

pub async fn start_summit() -> Result<()> {
    let mut child = Command::new(RETH_CONTROL_CMD)
        .arg("start")
        .arg(SEISMIC_SUMMIT_SERVICE)
        .spawn()
        .unwrap();

    let status = child.wait().unwrap();

    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("Failed to start summit"))
    }
}

pub async fn stop_summit() -> Result<()> {
    let mut child = Command::new(RETH_CONTROL_CMD)
        .arg("stop")
        .arg(SEISMIC_SUMMIT_SERVICE)
        .spawn()
        .unwrap();

    let status = child.wait().unwrap();

    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("Failed to stop summit"))
    }
}

pub fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> std::io::Result<()> {
    let src = src.as_ref();
    let dst = dst.as_ref();

    // Create the destination directory
    fs::create_dir_all(dst)?;

    // Iterate through the source directory
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_dir() {
            // Recursively copy subdirectories
            copy_dir_all(&src_path, &dst_path)?;
        } else {
            // Copy files
            fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}

/// Moves a file or folder from one location to another. First attempts rename(fastest method, works if on same filesystem) then tries copy+delete
pub fn rename_or_copy(src: impl AsRef<Path>, dest: impl AsRef<Path>) -> Result<()> {
    match fs::rename(&src, &dest) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
            // If rename fails due to crossing filesystems, copy and delete
            copy_dir_all(&src, dest)?;
            let _ = fs::remove_dir_all(src); // This failing isnt critical
            Ok(())
        }
        Err(e) => Err(e),
    }?;
    Ok(())
}
