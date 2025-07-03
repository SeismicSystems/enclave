//! Boot the enclave's key manager
use std::time::Duration;

use seismic_enclave::client::EnclaveClientBuilder;
use seismic_enclave::rpc::EnclaveApiClient;
use seismic_enclave::ENCLAVE_DEFAULT_ENDPOINT_IP;

/// Command to boot the enclave's key manager
#[tokio::main]
async fn main() {
    let port = 7878;
    let client = EnclaveClientBuilder::new()
        .ip(ENCLAVE_DEFAULT_ENDPOINT_IP.to_string())
        .port(port)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    client.boot_genesis().await.unwrap();
    client.complete_boot().await.unwrap();
}
