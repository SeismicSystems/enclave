use enclave_policies::install_all_policies;

#[tokio::main]
async fn main() {
    // println!("cargo:rerun-if-changed=src/utils/policy_fixture.rs");
    match install_all_policies().await {
        Ok(_) => {
            println!("Successfully installed all policies during build");
        }
        Err(e) => {
            panic!("Failed to install policies: {}", e);
        }
    }
}
