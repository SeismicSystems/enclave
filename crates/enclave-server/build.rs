use attestation_service::{token::simple::SimpleAttestationTokenBroker, AttestationService};
use seismic_enclave_server::utils::policy_fixture::PolicyFixture;

#[tokio::main]
async fn main() {
    println!("cargo:rerun-if-changed=src/utils/policy_fixture.rs");
    
    let as_config = attestation_service::config::Config::default();
    let mut verifier = AttestationService::new(as_config).await.unwrap();
    let fixture = PolicyFixture::all_policies();
    fixture.configure_verifier::<SimpleAttestationTokenBroker>(&mut verifier).await.unwrap();
    
    println!("Successfully installed all policies during build");
}