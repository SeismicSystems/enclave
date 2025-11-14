use crate::error::{Result, TdxInitError};
use regex::Regex;

const SSH_KEY_PATTERN: &str = r"^[A-Za-z0-9+/]{68}$";

pub fn validate_ssh_keys(keys: &[String]) -> Result<()> {
    if keys.is_empty() {
        return Err(TdxInitError::EmptyKeys);
    }

    let key_regex = Regex::new(SSH_KEY_PATTERN)
        .map_err(|e| TdxInitError::ServerError(format!("Invalid regex: {}", e)))?;

    for (index, key) in keys.iter().enumerate() {
        if !key_regex.is_match(key) {
            return Err(TdxInitError::InvalidSshKey {
                index,
                key: key.clone(),
            });
        }
    }

    Ok(())
}
