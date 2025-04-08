use crate::utils::policy_fixture::ALLOW_POLICY;
use attestation_service::token::simple::SimpleAttestationTokenBroker;
use base64::Engine;

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
    let mut saa = SeismicAttestationAgent::new(None, v_token_broker);

    // set the share_root policy to be the allow policy
    let encoded_policy = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ALLOW_POLICY);
    saa.set_policy("share_root".to_string(), encoded_policy)
        .await
        .unwrap();
    saa
}
