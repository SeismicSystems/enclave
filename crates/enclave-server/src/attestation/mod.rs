mod seismic_agent;
pub use seismic_agent::SeismicAttestationAgent;

use attestation_service::token::simple;

/// A reasonable default mock attestation agent for testing
pub async fn seismic_aa_mock() -> SeismicAttestationAgent {
    let token_broker_config = attestation_service::token::AttestationTokenConfig::Simple(
        simple::Configuration::default(),
    );
    let mut att_serv_config: attestation_service::config::Config = Default::default();
    att_serv_config.attestation_token_broker = token_broker_config;

    let saa = SeismicAttestationAgent::new(None, att_serv_config).await;
    saa
}
