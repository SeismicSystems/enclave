use enclave_policies::install_all_policies;

#[tokio::main]
async fn main() {
    // println!("cargo:rerun-if-changed=src/utils/policy_fixture.rs");
    install_all_policies();
    println!("Successfully installed all policies during build");
}
