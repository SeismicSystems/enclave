use anyhow::{Result, anyhow};
use dcap_rs::types::quotes::{body::QuoteBody, version_4::QuoteV4};
use enclave_contract::UpgradeOperator;

pub async fn verify_measurements_against_contract(quote: &QuoteV4) -> Result<()> {
    let QuoteBody::TD10QuoteBody(quote_body) = quote.quote_body else {
        return Err(anyhow!("Not a tdx quote"));
    };

    let measurements = UpgradeOperator::Measurements {
        tag: Default::default(),
        mrtd: quote_body.mrtd.into(),
        mrseam: quote_body.mrseam.into(),
        registrar_slots: vec![0, 1, 2, 3],
        registrar_values: vec![
            quote_body.rtmr0.into(),
            quote_body.rtmr1.into(),
            quote_body.rtmr2.into(),
            quote_body.rtmr3.into(),
        ],
    };

    // Get contract address and RPC URL from environment variables
    let upgrade_operator_address = enclave_contract::UPGRADE_OPERATOR_ADDRESS
        .parse::<alloy::primitives::Address>()
        .unwrap();

    let rpc_url = "http://localhost:8545"; // todo pass this down from cli args

    if enclave_contract::check_proposal_status(upgrade_operator_address, rpc_url, measurements)
        .await?
    {
        Ok(())
    } else {
        Err(anyhow!("Now approved"))
    }
}
