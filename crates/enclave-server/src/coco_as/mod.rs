pub mod handlers;
pub mod into_original;
pub mod policies;

use anyhow::Result;
use attestation_service::token::simple;
use attestation_service::token::AttestationTokenConfig;
use attestation_service::Data as OriginalData;
use attestation_service::HashAlgorithm as OriginalHashAlgorithm;
use attestation_service::{config::Config, AttestationService};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kbs_types::Tee;
use once_cell::sync::OnceCell;
use seismic_enclave::coco_as::ASCoreTokenClaims;
use std::sync::Arc;
use tokio::sync::RwLock;

pub static ATTESTATION_SERVICE: OnceCell<Arc<RwLock<AttestationService>>> = OnceCell::new();
// initializes the AttestationService
// which is reponsible for evaluating attestations
pub async fn init_coco_as(config: Option<Config>) -> Result<()> {
    // Check if the service is already initialized
    // This helps with multithreaded testing
    if ATTESTATION_SERVICE.get().is_some() {
        // AttestationService is already initialized, so we skip re-initialization.
        return Ok(());
    }

    let mut config = config.unwrap_or_default();
    config.attestation_token_broker =
        AttestationTokenConfig::Simple(simple::Configuration::default());

    // Initialize the AttestationService
    let coco_as = AttestationService::new(config)
        .await
        .expect("Failed to create an AttestationService");
    let lock = tokio::sync::RwLock::new(coco_as);
    ATTESTATION_SERVICE
        .set(Arc::new(lock))
        .map_err(|_| anyhow::anyhow!("Failed to set AttestationService"))?;

    // initialize the policies
    init_as_policies().await?;
    Ok(())
}

/// Initializes the AS policies from the policies directory
/// While every AS eval request checks that the evidence was created by a real enclave
/// A policy defines the expected values of that enclave.
///
/// For example, the important values for AxTdxVtpm are the MRSEAM and MRTD values,
/// which respectively fingerprint the TDX module and the guest firmware that are running
///
/// TODO: replace policies, particularly the Yocto policy, with finalized policies before mainnet
pub async fn init_as_policies() -> Result<()> {
    let coco_as = ATTESTATION_SERVICE.get().unwrap();
    let mut writeable_as = coco_as.write().await;

    let policies = vec![
        (policies::ALLOW_POLICY.to_string(), "allow".to_string()),
        (policies::DENY_POLICY.to_string(), "deny".to_string()),
        (policies::YOCTO_POLICY.to_string(), "yocto".to_string()),
    ];

    for (policy, policy_id) in policies {
        let policy_encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(policy);
        writeable_as
            .set_policy(policy_id.to_string(), policy_encoded)
            .await?;
    }

    Ok(())
}

// Call the evaluate function of the attestation service
// Gets back a b64 JWT web token of the form "header.claims.signature"
pub async fn eval_att_evidence(
    evidence: Vec<u8>,
    tee: Tee,
    runtime_data: Option<OriginalData>,
    runtime_data_hash_algorithm: OriginalHashAlgorithm,
    init_data: Option<OriginalData>,
    init_data_hash_algorithm: OriginalHashAlgorithm,
    policy_ids: Vec<String>,
) -> Result<String, anyhow::Error> {
    let coco_as = ATTESTATION_SERVICE.get().unwrap();
    let readable_as = coco_as.read().await;

    readable_as
        .evaluate(
            evidence,
            tee,
            runtime_data,
            runtime_data_hash_algorithm,
            init_data,
            init_data_hash_algorithm,
            policy_ids,
        )
        .await
}

// parses the b64 JWT token retuned by the attestation service
pub fn parse_as_token_claims(as_token: &str) -> Result<ASCoreTokenClaims, anyhow::Error> {
    let parts: Vec<&str> = as_token.splitn(3, '.').collect();
    let claims_b64 = parts[1];
    let claims_decoded_bytes = URL_SAFE_NO_PAD.decode(claims_b64)?;
    let claims_decoded_string = String::from_utf8(claims_decoded_bytes)?;
    let claims: ASCoreTokenClaims = serde_json::from_str(&claims_decoded_string)?;

    Ok(claims)
}
