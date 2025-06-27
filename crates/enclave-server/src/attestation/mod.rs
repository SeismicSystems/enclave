mod seismic_agent;
pub use seismic_agent::SeismicAttestationAgent;

use attestation_service::token::simple;

/// A reasonable default mock attestation agent for testing
pub async fn seismic_aa_mock() -> SeismicAttestationAgent {
    let att_serv_config = simple_att_serv_config();

    let saa = SeismicAttestationAgent::new(None, att_serv_config).await;
    saa
}

pub fn simple_att_serv_config() -> attestation_service::config::Config {
    let token_broker_config = simple_token_broker_config();
    let mut att_serv_config: attestation_service::config::Config = Default::default();
    att_serv_config.attestation_token_broker = token_broker_config;
    att_serv_config
}

pub fn simple_token_broker_config() -> attestation_service::token::AttestationTokenConfig {
    attestation_service::token::AttestationTokenConfig::Simple(
        simple::Configuration::default(),
    )
}
