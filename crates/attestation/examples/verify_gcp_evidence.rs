//! DCAP-verify a `summit-key-holder` `/v1/quote` response captured on GCP.
//!
//! Usage: `verify_gcp_evidence <quote-response.json> <nonce-hex>`

use seismic_attestation::bindings::{binding64_from_digest32, founding_summit_keys_binding};
use seismic_attestation::{
    AttestationExchangeMessage, AttestationType, SeismicMeasurementPolicy, VerifyOptions,
    verify_evidence_with_policy,
};

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("quote-response.json path");
    let nonce: [u8; 32] = unhex(&args.next().expect("nonce hex"));
    let raw = std::fs::read(&path).expect("read response");
    let resp: serde_json::Value = serde_json::from_slice(&raw).expect("json");
    let node_pk: [u8; 32] = unhex(resp["node_public_key"].as_str().unwrap());
    let consensus_pk: [u8; 48] = unhex(resp["consensus_public_key"].as_str().unwrap());
    let evidence: AttestationExchangeMessage =
        serde_json::from_value(resp["evidence"].clone()).expect("evidence");
    let binding = binding64_from_digest32(founding_summit_keys_binding(
        &nonce,
        &node_pk,
        &consensus_pk,
    ));
    println!("attestation_type: {:?}", evidence.attestation_type());
    println!(
        "expected report_data: {}",
        binding
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );

    let policy =
        SeismicMeasurementPolicy::dangerously_accept_any_for_testing(AttestationType::GcpTdx);
    match verify_evidence_with_policy(evidence, binding, policy, VerifyOptions::default()).await {
        Ok(verified) => {
            println!("VERIFIED");
            println!("{:#?}", verified.attestation);
            let snap = format!("{:?}", verified.collateral);
            println!("collateral: {}…", &snap[..snap.len().min(600)]);
        }
        Err(e) => {
            println!("FAILED: {e}");
            println!("{e:#?}");
            std::process::exit(1);
        }
    }
}
