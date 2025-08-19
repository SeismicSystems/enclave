use seismic_enclave_server::utils::policy_fixture::install_all_policies;

#[tokio::main]
async fn main() {
    match install_all_policies().await {
        Ok(_) => {
            println!("Installed all policies");
        }
        Err(e) => {
            panic!("Failed to install policies: {}", e);
        }
    }
}