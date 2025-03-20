use jsonrpsee::core::RpcResult;
use tracing::error;

use super::into_original::*;
use super::{eval_att_evidence, parse_as_token_claims};
use attestation_service::Data as OriginalData;
use attestation_service::HashAlgorithm as OriginalHashAlgorithm;
use seismic_enclave::rpc_bad_evidence_error;
use seismic_enclave::{request_types::coco_as::*, rpc_bad_argument_error};

use super::into_original::IntoOriginalHashAlgorithm;

/// Handles attestation evidence verification.
///
/// This function is responsible for evaluating the provided attestation evidence and ensuring its validity.
/// The attestation service checks the following criteria:
///
/// 1. **Internal Consistency of Evidence:**
///    - Verifies that the provided evidence is consistent with itself through the AS verifier dependency
///    - Ex checks that the evidence data matches the TEE's signature.
///    - Ex checks that the init_data and runtime_data in the request match with the attestation evidence.
///    - Also includes a call to the PCCS to verify the TEE public key is valid
///
/// 2. **Comparison with Reference Values (RVPS):**
///    - Validates the evidence against trusted reference values provided by the **Reference Value Provider Service (RVPS)**.
///    - These reference values are typically supplied by the manufacturer or another trusted entity and represent the expected state of the platform.
///
/// 3. **TEE State Compliance with Attestation Service (AS) Policy:**
///    - Ensures that the TEE state aligns with the security policies defined by the attestation service.
///    - This includes confirming that the correct software is running within the TEE
pub async fn attestation_eval_evidence_handler(
    request: AttestationEvalEvidenceRequest,
) -> RpcResult<AttestationEvalEvidenceResponse> {
    // Convert the request's runtime data hash algorithm to the original enum
    let runtime_data: Option<OriginalData> = request.runtime_data.map(|data| data.into_original());
    let runtime_data_hash_algorithm: OriginalHashAlgorithm =
        match request.runtime_data_hash_algorithm {
            Some(alg) => alg.into_original(),
            None => OriginalHashAlgorithm::Sha256,
        };

    // Call the evaluate function of the attestation service
    // Gets back a b64 JWT web token of the form "header.claims.signature"
    let eval_result = eval_att_evidence(
        request.evidence,
        request.tee,
        runtime_data,
        runtime_data_hash_algorithm,
        None,                          // hardcoded because AzTdxVtpm doesn't support init data
        OriginalHashAlgorithm::Sha256, // dummy val to make this compile
        request.policy_ids,
    )
    .await;

    let as_token: String = match eval_result {
        Ok(as_token) => as_token,
        Err(e) => {
            error!("Failed to evaluate attestation evidence: {}", e);
            return Err(rpc_bad_evidence_error(e));
        }
    };

    let claims: ASCoreTokenClaims = match parse_as_token_claims(&as_token) {
        Ok(claims) => claims,
        Err(e) => {
            error!("Failed to parse AS token: {}", e);
            return Err(rpc_bad_argument_error(anyhow::anyhow!(
                "Error while parsing AS token: {e}"
            )));
        }
    };

    Ok(AttestationEvalEvidenceResponse {
        eval: true,
        claims: Some(claims),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        coco_as::init_coco_as,
        utils::test_utils::{is_sudo, read_vector_txt},
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use kbs_types::Tee;
    use serde_json::Value;
    use serial_test::serial;
    use std::env;

    #[test]
    fn test_parse_as_token() {
        match env::current_dir() {
            Ok(path) => println!("Current directory: {}", path.display()),
            Err(e) => eprintln!("Error getting current directory: {}", e),
        }
        let ex_token_path = "../../examples/as_token.txt"; // assumes tests are run from enclaver-server dir
        let ex_token = std::fs::read_to_string(ex_token_path).unwrap();

        let claims = parse_as_token_claims(&ex_token).unwrap();

        assert_eq!(claims.tee, "aztdxvtpm");
        let evaluation_reports = serde_json::to_string(&claims.evaluation_reports).unwrap();
        assert_eq!(evaluation_reports, "[{\"policy-hash\":\"b3b555df21b9e952384aec5e81e03e53ca82741da3c5d055ccdb6ba5a85dcc2e6fd1196819dc3c26d09471735275b30a\",\"policy-id\":\"yocto\"}]");
        let tcb_status_map: serde_json::Map<String, Value> =
            serde_json::from_str(&claims.tcb_status).unwrap();
        assert_eq!(
            tcb_status_map.get("aztdxvtpm.quote.body.mr_td"),
            Some(&Value::String("bb379f8e734a755832509f61403f99db2258a70a01e1172a499d6d364101b0675455b4e372a35c1f006541f2de0d7154".to_string()))
        );
        assert_eq!(claims.customized_claims.init_data, Value::Null);
        assert_eq!(claims.customized_claims.runtime_data, Value::Null);
    }

    #[tokio::test]
    #[serial(attestation_service)]
    async fn test_eval_evidence_sample() {
        // handle set up permissions
        if !is_sudo() {
            panic!("test_eval_evidence_sample: skipped (requires sudo privileges)");
        }

        // Initialize ATTESTATION_SERVICE
        init_coco_as(None)
            .await
            .expect("Failed to initialize AttestationService");

        // Mock a valid AttestationEvalEvidenceRequest
        let eval_request = AttestationEvalEvidenceRequest {
            evidence: vec![
                123, 34, 115, 118, 110, 34, 58, 34, 49, 34, 44, 34, 114, 101, 112, 111, 114, 116,
                95, 100, 97, 116, 97, 34, 58, 34, 98, 109, 57, 117, 89, 50, 85, 61, 34, 125,
            ], // Example evidence data
            tee: Tee::Sample,
            runtime_data: Some(Data::Raw("nonce".as_bytes().to_vec())), // Example runtime data
            runtime_data_hash_algorithm: Some(HashAlgorithm::Sha256),
            policy_ids: vec!["allow".to_string()],
        };

        // Call the handler
        let eval_evidence_response = attestation_eval_evidence_handler(eval_request)
            .await
            .unwrap();

        assert!(eval_evidence_response.eval);
        let claims = eval_evidence_response.claims.unwrap();
        assert_eq!(claims.tee, "sample");
        let tcb_status_map: serde_json::Map<String, Value> =
            serde_json::from_str(&claims.tcb_status).unwrap();
        assert_eq!(tcb_status_map["report_data"], "bm9uY2U=");
    }

    #[tokio::test]
    #[serial(attestation_service)]
    async fn test_eval_evidence_az_tdx() {
        // handle set up permissions
        if !is_sudo() {
            panic!("test_eval_evidence_az_tdx: skipped (requires sudo privileges)");
        }

        // Initialize ATTESTATION_SERVICE
        init_coco_as(None)
            .await
            .expect("Failed to initialize AttestationService");

        // Mock a valid AttestationEvalEvidenceRequest
        let tdx_evidence_encoded =
            std::fs::read_to_string("../../examples/tdx_encoded_evidence.txt").unwrap();
        let tdx_evidence = URL_SAFE_NO_PAD
            .decode(tdx_evidence_encoded.as_str())
            .unwrap();

        let tdx_eval_request = AttestationEvalEvidenceRequest {
            evidence: tdx_evidence,
            tee: Tee::AzTdxVtpm,
            runtime_data: Some(Data::Raw("".into())),
            runtime_data_hash_algorithm: None,
            policy_ids: vec!["allow".to_string()],
        };

        // Call the handler
        let eval_evidence_response = attestation_eval_evidence_handler(tdx_eval_request)
            .await
            .unwrap();

        assert!(eval_evidence_response.eval);
        let claims = eval_evidence_response.claims.unwrap();

        assert_eq!(claims.tee, "aztdxvtpm");
        let evaluation_reports = serde_json::to_string(&claims.evaluation_reports).unwrap();
        assert_eq!(evaluation_reports, "[{\"policy-hash\":\"fbb1cf91bb453d7c89b04cbc8d727dc142c47d84c5c9c2012b8c86d4d1892874743a63f7448e592ca6bee9cfeb286732\",\"policy-id\":\"allow\"}]");
        let tcb_status_map: serde_json::Map<String, Value> =
            serde_json::from_str(&claims.tcb_status).unwrap();
        assert_eq!(
            tcb_status_map.get("aztdxvtpm.quote.body.mr_td"),
            Some(&Value::String("bb379f8e734a755832509f61403f99db2258a70a01e1172a499d6d364101b0675455b4e372a35c1f006541f2de0d7154".to_string()))
        );
        assert_eq!(claims.customized_claims.init_data, Value::Null);
        assert_eq!(claims.customized_claims.runtime_data, Value::Null);
    }

    #[tokio::test]
    #[serial(attestation_service)]
    async fn test_eval_policy_deny() {
        // handle set up permissions
        if !is_sudo() {
            panic!("test_eval_evidence_az_tdx: skipped (requires sudo privileges)");
        }

        // Initialize ATTESTATION_SERVICE
        init_coco_as(None)
            .await
            .expect("Failed to initialize AttestationService");

        // Mock a valid AttestationEvalEvidenceRequest
        let eval_request = AttestationEvalEvidenceRequest {
            evidence: vec![
                123, 34, 115, 118, 110, 34, 58, 34, 49, 34, 44, 34, 114, 101, 112, 111, 114, 116,
                95, 100, 97, 116, 97, 34, 58, 34, 98, 109, 57, 117, 89, 50, 85, 61, 34, 125,
            ], // Example evidence data
            tee: Tee::Sample,
            runtime_data: Some(Data::Raw("nonce".as_bytes().to_vec())), // Example runtime data
            runtime_data_hash_algorithm: Some(HashAlgorithm::Sha256),
            policy_ids: vec!["deny".to_string()],
        };

        // Call the handler
        let eval_evidence_response = attestation_eval_evidence_handler(eval_request).await;

        assert!(
            eval_evidence_response.is_err(),
            "Expected error for deny policy {:?}",
            eval_evidence_response.err().unwrap()
        );
    }

    #[tokio::test]
    #[serial(attestation_service)]
    async fn test_eval_evidence_az_tdx_tpm_pcr04() {
        println!("starting test_eval_evidence_az_tdx_tpm_pcr04");
        // handle set up permissions
        if !is_sudo() {
            panic!("test_eval_evidence_az_tdx_tpm_pcr04: skipped (requires sudo privileges)");
        }

        init_coco_as(None)
            .await
            .expect("Failed to initialize AttestationService");

        // Make a passing request to validate using a policy that checks mr_td, mr_seam, and pcr04
        let az_tdx_evidence: Vec<u8> =
            read_vector_txt("../../examples/yocto_20241023223507.txt".to_string()).unwrap(); // assumes tests are run from enclaver-server dir
        let runtime_data_bytes = vec![
            240, 30, 194, 3, 67, 143, 162, 40, 249, 35, 238, 193, 59, 140, 203, 3, 98, 144, 105,
            221, 209, 34, 207, 229, 52, 61, 58, 14, 102, 234, 146, 8,
        ];
        let test_policy_id = "yocto".to_string();
        let tdx_eval_request = AttestationEvalEvidenceRequest {
            evidence: az_tdx_evidence,
            tee: Tee::AzTdxVtpm,
            runtime_data: Some(Data::Raw(runtime_data_bytes)),
            runtime_data_hash_algorithm: None,
            policy_ids: vec![test_policy_id.clone()],
        };

        let _eval_evidence_response = attestation_eval_evidence_handler(tdx_eval_request)
            .await
            .unwrap();

        // Make a failing request to validate using a policy that checks mr_td, mr_seam, and pcr04
        let az_tdx_evidence: Vec<u8> =
            read_vector_txt("../../examples/yocto_20241025193121.txt".to_string()).unwrap();
        let runtime_data_bytes = vec![
            240, 30, 194, 3, 67, 143, 162, 40, 249, 35, 238, 193, 59, 140, 203, 3, 98, 144, 105,
            221, 209, 34, 207, 229, 52, 61, 58, 14, 102, 234, 146, 8,
        ];
        let tdx_eval_request = AttestationEvalEvidenceRequest {
            evidence: az_tdx_evidence,
            tee: Tee::AzTdxVtpm,
            runtime_data: Some(Data::Raw(runtime_data_bytes)),
            runtime_data_hash_algorithm: None,
            policy_ids: vec!["yocto".to_string()],
        };

        let eval_evidence_response = attestation_eval_evidence_handler(tdx_eval_request).await;
        let expected_err_msg = format!("Reject by policy {test_policy_id}");
        let err_msg = eval_evidence_response.err().unwrap().to_string();
        assert!(
            err_msg.contains(&expected_err_msg),
            "Response does not contain expected message. Expected to see: \"{expected_err_msg}\", Was: {err_msg}"
        );
    }
}
