// use anyhow::{anyhow, Result};
// use base64::engine::general_purpose::URL_SAFE_NO_PAD;
// use base64::Engine;
// use serde::{Deserialize, Serialize};
// use serde_json::Value;
// use std::collections::HashMap;


// /// Struct representing the relevant fields of an Attestation Service (AS) token's claims.
// ///
// /// This struct contains information about the Trusted Execution Environment (TEE),
// /// the evaluation of evidence, and various security properties attested by the AS.
// ///
// /// # Fields
// ///
// /// - `tee` - The TEE type of the attestation evidence.
// /// - `evaluation_reports` - A list of policies that the evidence was evaluated against.  
// ///   More information can be found in the [policy documentation](https://github.com/confidential-containers/trustee/blob/bd6b25add83ece4bb5204b8cf560e0727a7c3f8e/attestation-service/docs/policy.md).
// /// - `tcb_status` - The Trusted Computing Base (TCB) status that was attested to.  
// ///   This is verified against the hardware signature and then checked against a policy.
// /// - `reference_data` - Reference values provided by the Reference Value Provider Service (RVPS)  
// ///   to check against the attestation evidence.
// /// - `customized_claims` - The initialization and runtime data that were enforced to match the evidence.
// #[derive(Debug, Serialize, Deserialize, Clone)]
// pub struct ASCoreTokenClaims {
//     pub tee: String,
//     #[serde(rename = "evaluation-reports")]
//     pub evaluation_reports: Vec<Value>,
//     #[serde(rename = "tcb-status")]
//     pub tcb_status: String,
//     pub customized_claims: ASCustomizedClaims,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub reference_data: Option<HashMap<String, String>>,
// }


// /// Represents the customized claims for initialization and runtime data.
// #[derive(Debug, Serialize, Deserialize, Clone, Default)]
// pub struct ASCustomizedClaims {
//     pub init_data: Value,
//     pub runtime_data: Value,
// }

// /// Default implementation for ASCoreTokenClaims
// impl Default for ASCoreTokenClaims {
//     fn default() -> Self {
//         Self {
//             tee: "unknown".to_string(),
//             evaluation_reports: Vec::new(),
//             tcb_status: "unknown".to_string(),
//             customized_claims: ASCustomizedClaims::default(),
//             reference_data: None,
//         }
//     }
// }


// impl ASCoreTokenClaims {
//     /// Serializes the claims to JSON (without JWT encoding).
//     pub fn to_json(&self) -> Result<String> {
//         Ok(serde_json::to_string(self)?)
//     }

//     /// Parses a (base64-encoded) JWT string into an `ASCoreTokenClaims`.
//     ///
//     /// Expects the token to have three parts separated by '.', and
//     /// decodes the middle part as JSON claims.
//     pub fn from_jwt(token: &str) -> Result<Self> {
//         let parts: Vec<&str> = token.splitn(3, '.').collect();
//         if parts.len() != 3 {
//             return Err(anyhow!("Invalid token format: expected 3 parts separated by '.'"));
//         }
//         let claims_b64 = parts[1];
//         let claims_decoded_bytes = URL_SAFE_NO_PAD.decode(claims_b64)?;
//         let claims_decoded_string = String::from_utf8(claims_decoded_bytes)?;
//         let claims: ASCoreTokenClaims = serde_json::from_str(&claims_decoded_string)?;
//         Ok(claims)
//     }
// }
