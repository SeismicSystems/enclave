use crate::config::{ArgsConfig, DefaultArgs, LogConfig};
use crate::error::{Result, TdxInitError};

const VALID_LOG_LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error"];

pub fn validate_arguments(args: &ArgsConfig) -> Result<()> {
    let default_args = DefaultArgs::new();

    if let Some(reth_args) = &args.reth {
        validate_binary_args("reth", reth_args, &default_args.get_reth_flag_names())?;
    }

    if let Some(summit_args) = &args.summit {
        validate_binary_args("summit", summit_args, &default_args.get_summit_flag_names())?;
    }

    if let Some(enclave_args) = &args.enclave {
        validate_binary_args(
            "enclave",
            enclave_args,
            &default_args.get_enclave_flag_names(),
        )?;
    }

    Ok(())
}

pub fn validate_log_config(log_config: &LogConfig) -> Result<()> {
    if let Some(summit_level) = &log_config.summit {
        validate_log_level("summit", summit_level)?;
    }

    if let Some(reth_level) = &log_config.reth {
        validate_log_level("reth", reth_level)?;
    }

    if let Some(enclave_level) = &log_config.enclave {
        validate_log_level("enclave", enclave_level)?;
    }

    Ok(())
}

fn validate_binary_args(binary: &str, user_args: &str, default_flags: &[&str]) -> Result<()> {
    let user_tokens: Vec<&str> = user_args.split_whitespace().collect();

    // Check if any user arguments conflict with default arguments
    for user_token in &user_tokens {
        // Skip values (arguments that don't start with -)
        if !user_token.starts_with('-') {
            continue;
        }

        // Extract the flag name (handle both --flag and --flag=value formats)
        let flag_name = if let Some(eq_pos) = user_token.find('=') {
            &user_token[..eq_pos]
        } else {
            user_token
        };

        // Check if this flag exists in default arguments
        if default_flags.contains(&flag_name) {
            return Err(TdxInitError::ConflictingArgument {
                binary: binary.to_string(),
                arg: flag_name.to_string(),
            });
        }
    }

    Ok(())
}

fn validate_log_level(binary: &str, level: &str) -> Result<()> {
    if !VALID_LOG_LEVELS.contains(&level.to_lowercase().as_str()) {
        return Err(TdxInitError::InvalidLogLevel {
            binary: binary.to_string(),
            level: level.to_string(),
        });
    }
    Ok(())
}
