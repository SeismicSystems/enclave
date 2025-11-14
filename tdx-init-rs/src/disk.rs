use crate::error::Result;
use crate::error::TdxInitError;

use glob::glob;
use std::path::PathBuf;
use tracing::{info, warn};

const PERSISTENT_DISK_GLOB: &str = "/dev/disk/by-path/*10";
const GLOB_PATTERNS_FILE: &str = "/etc/tdx-init/disk-glob";

pub async fn discover_persistent_disk() -> Result<Option<PathBuf>> {
    let patterns = read_glob_patterns().await;

    for pattern in patterns {
        if let Some(device) = try_pattern(&pattern)? {
            return Ok(Some(device));
        }
    }
    Ok(None)
}

fn try_pattern(pattern: &str) -> Result<Option<PathBuf>> {
    let paths = glob(pattern).map_err(TdxInitError::GlobPatternError)?;
    let mut devices = Vec::new();
    for path_result in paths {
        let path = path_result.map_err(|e| TdxInitError::GlobError(e))?;
        devices.push(path);
    }
    match devices.len() {
        0 => Ok(None),
        1 => {
            info!("Using persistent disk device: {}", devices[0].display());
            Ok(Some(devices[0].clone()))
        }
        _ => {
            warn!(
                "Multiple devices found by pattern '{}': {:?}",
                pattern, devices
            );
            info!("Using persistent disk device: {}", devices[0].display());
            Ok(Some(devices[0].clone()))
        }
    }
}

async fn read_glob_patterns() -> Vec<String> {
    let mut patterns = vec![PERSISTENT_DISK_GLOB.to_string()];
    if let Ok(data) = std::fs::read_to_string(GLOB_PATTERNS_FILE) {
        let trimmed = data.trim();
        if !data.is_empty() {
            patterns.extend(trimmed.split('\n').map(|line| line.trim().to_string()));
        }
    }
    patterns
}
