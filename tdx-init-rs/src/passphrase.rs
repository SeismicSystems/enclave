use crate::error::Result;
use crate::persistence;
use std::path::PathBuf;
use crate::config::InitConfig;
use tokio::fs;
use rand::distr::{Alphanumeric, Distribution, SampleString};

const MOUNT_POINT: &str = "/proc/mounts";

pub fn generate_random_passphrase() -> Result<String> {
    let passphrase = Alphanumeric.sample_string(&mut rand::rng(), 16);
    Ok(passphrase)
}

pub async fn set_passphrase(device_path: PathBuf) -> Result<()> {
    // print!("Enter passphrase: ");
    // use std::io::{self, Write};
    // io::stdout().flush().unwrap();

    // let mut passphrase = String::new();
    // io::stdin().read_line(&mut passphrase)?;
    // let passphrase = passphrase.trim().to_string();

    let passphrase = generate_random_passphrase()?;
    let config = persistence::read_temp_config().await?;
    initialize_with_passphrase(device_path, passphrase, &config).await?;

    Ok(())
}

pub async fn initialize_with_passphrase(
    _device_path: PathBuf,
    _passphrase: String,
    _config: &InitConfig,
) -> Result<()> {
    todo!("Implement LUKS initialization")
}


async fn is_mounted() -> Result<bool> {
    match fs::read_to_string(MOUNT_POINT).await {
        Ok(content) => Ok(content.contains(&format!(" {} ", MOUNT_POINT))),
        Err(_) => Ok(false),
    }
}