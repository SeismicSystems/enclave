use crate::config::InitConfig;
use crate::error::{Result, TdxInitError};
use crate::luks::{self, MAPPER_DEVICE};
use crate::utils::{
    command::execute_command,
    file::{create_dir_with_perms, set_file_permissions, set_ownership},
    mac::{compute_mac, read_mac_from_device, verify_mac, write_mac_to_device},
};
use crate::persistence;
use rand::distr::Alphanumeric;
use rand::Rng;
use std::path::PathBuf;
use tokio::fs;
use tracing::{info, warn};

const MOUNT_POINT: &str = "/persistent";
const KEY_FILE: &str = "/etc/searcher_key";
const TEMP_CONFIG_FILE: &str = "/etc/tdx-init/config.json";

pub fn generate_random_passphrase() -> Result<String> {
    let passphrase = rand::rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect();
    Ok(passphrase)
}

fn get_user_passphrase() -> Result<String> {
    print!("Enter passphrase: ");
    use std::io::{self, Write};
    io::stdout().flush().unwrap();

    let mut passphrase = String::new();
    io::stdin().read_line(&mut passphrase)?;
    Ok(passphrase.trim().to_string())
}

async fn validate_prerequisites() -> Result<()> {
    if is_mounted().await? {
        return Err(TdxInitError::AlreadyMounted);
    }

    if !fs::try_exists(KEY_FILE).await.unwrap_or(false) {
        return Err(TdxInitError::SshKeyNotFound);
    }

    if !fs::try_exists(TEMP_CONFIG_FILE).await.unwrap_or(false) {
        return Err(TdxInitError::ConfigNotFound(
            "Config not found. Provide configuration via HTTP first.".to_string()
        ));
    }

    Ok(())
}

async fn is_mounted() -> Result<bool> {
    match fs::read_to_string("/proc/mounts").await {
        Ok(content) => Ok(content.contains(&format!(" {} ", MOUNT_POINT))),
        Err(_) => Ok(false),
    }
}

async fn create_filesystem() -> Result<()> {
    info!("Creating ext4 filesystem...");
    match execute_command("mkfs.ext4", &[MAPPER_DEVICE]).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = luks::close_luks_container().await;
            Err(e)
        }
    }
}

async fn mount_filesystem() -> Result<()> {
    create_dir_with_perms(&PathBuf::from(MOUNT_POINT), 0o755).await?;
    match execute_command("mount", &[MAPPER_DEVICE, MOUNT_POINT]).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = luks::close_luks_container().await;
            Err(e)
        }
    }
}

async fn unmount_filesystem() -> Result<()> {
    execute_command("umount", &[MOUNT_POINT]).await
}


async fn create_mount_directories() -> Result<()> {
    let dirs = ["searcher", "delayed_logs", "searcher_logs", "conf"];
    
    for dir in &dirs {
        let path = format!("{}/{}", MOUNT_POINT, dir);
        fs::create_dir_all(&path).await?;
    }
    
    Ok(())
}

async fn set_directory_permissions() -> Result<()> {
    set_ownership(format!("{}/searcher", MOUNT_POINT), 1000, 1000).await?;
    set_ownership(format!("{}/searcher_logs", MOUNT_POINT), 1000, 1000).await?;
    set_file_permissions(format!("{}/searcher_logs", MOUNT_POINT), 0o755).await?;
    Ok(())
}

async fn setup_mount_dirs() -> Result<()> {
    create_mount_directories().await?;
    set_directory_permissions().await?;
    copy_config_to_persistent().await;
    Ok(())
}

async fn copy_config_to_persistent() {
    if let Ok(config) = persistence::read_temp_config().await {
        if let Err(e) = persistence::copy_config_to_persistent(&config).await {
            warn!("Warning: Could not copy config to persistent storage: {}", e);
        }
    }
}

async fn cleanup_mount() {
    let _ = unmount_filesystem().await;
    let _ = luks::close_luks_container().await;
    luks::cleanup_header_file().await;
}

async fn setup_new_disk(device_path: PathBuf, passphrase: String) -> Result<()> {
    luks::cleanup_header_file().await;
    
    luks::format_luks_device(&device_path, &passphrase).await?;
    
    let ssh_key = match fs::read_to_string(KEY_FILE).await {
        Ok(key) => key,
        Err(_) => {
            cleanup_mount().await;
            return Err(TdxInitError::SshKeyNotFound);
        }
    };
    
    let config_data = fs::read_to_string(TEMP_CONFIG_FILE).await.ok();
    
    let token = luks::create_luks_token(&ssh_key, config_data).await?;
    
    match luks::import_luks_token(&token).await {
        Ok(()) => (),
        Err(e) => {
            cleanup_mount().await;
            return Err(e);
        }
    }
    
    luks::restore_header_to_device(&device_path).await?;
    
    let mac = compute_mac(&passphrase, luks::HEADER_FILE).await?;
    write_mac_to_device(&device_path, &mac).await?;
    
    luks::open_luks_container(&device_path, &passphrase).await?;
    create_filesystem().await?;
    mount_filesystem().await?;
    
    luks::cleanup_header_file().await;
    info!("Encrypted disk initialized and mounted successfully");
    Ok(())
}

async fn mount_existing_disk(device_path: PathBuf, passphrase: String) -> Result<()> {
    luks::cleanup_header_file().await;
    
    luks::backup_header_from_device(&device_path).await?;
    
    let expected_mac = read_mac_from_device(&device_path).await?;
    
    info!("Verifying header integrity...");
    if let Err(e) = verify_mac(&passphrase, luks::HEADER_FILE, &expected_mac).await {
        luks::cleanup_header_file().await;
        return Err(e);
    }
    
    match luks::open_luks_container(&device_path, &passphrase).await {
        Ok(()) => {
            luks::cleanup_header_file().await;
            mount_filesystem().await?;
            copy_config_to_persistent().await;
            info!("Encrypted disk mounted successfully");
            Ok(())
        }
        Err(e) => {
            luks::cleanup_header_file().await;
            Err(e)
        }
    }
}

pub async fn set_passphrase(device_path: PathBuf) -> Result<()> {
    validate_prerequisites().await?;
    
    let is_new_setup = !luks::is_luks_device(&device_path).await?;
    let passphrase = get_user_passphrase()?;

    if is_new_setup {
        setup_new_disk(device_path, passphrase).await?;
        setup_mount_dirs().await?;
    } else {
        mount_existing_disk(device_path, passphrase).await?;
    }

    Ok(())
}

pub async fn initialize_with_passphrase(
    device_path: PathBuf,
    passphrase: String,
    _config: &InitConfig,
) -> Result<()> {
    if is_mounted().await? {
        return Err(TdxInitError::AlreadyMounted);
    }

    let is_new_setup = !luks::is_luks_device(&device_path).await?;

    if is_new_setup {
        setup_new_disk(device_path, passphrase).await?;
        setup_mount_dirs().await?;
    } else {
        mount_existing_disk(device_path, passphrase).await?;
    }

    Ok(())
}