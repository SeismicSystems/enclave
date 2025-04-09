use attestation_service::token::simple::SimpleAttestationTokenBroker;

mod seismic_agent;
mod verifier;

// re-exports
pub use seismic_agent::SeismicAttestationAgent;
pub use verifier::DcapAttVerifier;

/// A reasonable default mock attestation agent for testing
pub async fn seismic_aa_mock() -> SeismicAttestationAgent<SimpleAttestationTokenBroker> {
    let v_token_broker = SimpleAttestationTokenBroker::new(
        attestation_service::token::simple::Configuration::default(),
    )
    .expect("Failed to create an AttestationAgent");
    let saa = SeismicAttestationAgent::new(None, v_token_broker);
    saa
}
