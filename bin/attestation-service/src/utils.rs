use tracing::info;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

/// The raw TPM device quote generation opens (az-cvm-vtpm hardcodes
/// tss-esapi's default TCTI).
const TPM_DEVICE: &str = "/dev/tpm0";

/// Panic unless this process can open [`TPM_DEVICE`] read-write: as root, or
/// as a member of the group the device is assigned to. The open also fails
/// while another process holds the device, which live-TEE tests cannot share
/// either. The device is closed again before this returns.
pub fn require_tpm_access(test: &str) {
    if let Err(err) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(TPM_DEVICE)
    {
        panic!("{test}: cannot open {TPM_DEVICE} ({err}); see tests/README.md");
    }
}

pub fn init_tracing() {
    // Read log level from RUST_LOG, default to "info" if unset — the same
    // default as the custodian service and the production unit files.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = FmtSubscriber::builder().with_env_filter(filter).finish();

    // Keep the first subscriber on repeat calls: every integration test in
    // the shared test process initializes tracing.
    if tracing::subscriber::set_global_default(subscriber).is_ok() {
        info!("Attestation service tracing initialized");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every integration test in one process initializes tracing; a repeat
    // call must keep the first subscriber rather than panic.
    #[test]
    fn init_tracing_is_idempotent() {
        init_tracing();
        init_tracing();
    }
}
