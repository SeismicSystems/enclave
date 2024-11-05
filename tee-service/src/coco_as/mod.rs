pub mod handlers;
pub mod into_original;
pub mod policies;

use crate::ATTESTATION_SERVICE;
use attestation_service::Data as OriginalData;
use attestation_service::HashAlgorithm as OriginalHashAlgorithm;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kbs_types::Tee;
use tee_service_api::coco_as::ASCoreTokenClaims;

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
    let eval_result = readable_as
        .evaluate(
            evidence,
            tee,
            runtime_data,
            runtime_data_hash_algorithm,
            init_data,
            init_data_hash_algorithm,
            policy_ids,
        )
        .await;
    eval_result
}

// parses the b64 JWT token retuned by the attestation service
fn parse_as_token_claims(as_token: &str) -> Result<ASCoreTokenClaims, anyhow::Error> {
    let parts: Vec<&str> = as_token.splitn(3, '.').collect();
    let claims_b64 = parts[1];
    let claims_decoded_bytes = URL_SAFE_NO_PAD.decode(claims_b64)?;
    let claims_decoded_string = String::from_utf8(claims_decoded_bytes)?;
    let claims: ASCoreTokenClaims = serde_json::from_str(&claims_decoded_string)?;

    Ok(claims)
}
