use hyper::{body::to_bytes, Body, Request, Response};
use std::convert::Infallible;

use super::into_original::*;
use super::{eval_att_evidence, parse_as_token_claims};
use attestation_service::Data as OriginalData;
use attestation_service::HashAlgorithm as OriginalHashAlgorithm;
use seismic_enclave::errors::{
    bad_evidence_response, invalid_json_body_resp, invalid_req_body_resp,
};
use seismic_enclave::request_types::coco_as::*;

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
    req: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    // Parse the request body
    let body_bytes = match to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(invalid_req_body_resp());
        }
    };

    // Deserialize the request body into the evaluate request struct
    let evaluate_request: AttestationEvalEvidenceRequest = match serde_json::from_slice(&body_bytes)
    {
        Ok(request) => request,
        Err(_) => {
            return Ok(invalid_json_body_resp());
        }
    };

    // Convert the request's runtime data hash algorithm to the original enum
    let runtime_data: Option<OriginalData> = evaluate_request
        .runtime_data
        .map(|data| data.into_original());
    let runtime_data_hash_algorithm: OriginalHashAlgorithm =
        match evaluate_request.runtime_data_hash_algorithm {
            Some(alg) => alg.into_original(),
            None => OriginalHashAlgorithm::Sha256,
        };

    // Call the evaluate function of the attestation service
    // Gets back a b64 JWT web token of the form "header.claims.signature"
    let eval_result = eval_att_evidence(
        evaluate_request.evidence,
        evaluate_request.tee,
        runtime_data,
        runtime_data_hash_algorithm,
        None,                          // hardcoded because AzTdxVtpm doesn't support init data
        OriginalHashAlgorithm::Sha256, // dummy val to make this compile
        evaluate_request.policy_ids,
    )
    .await;

    let as_token: String = match eval_result {
        Ok(as_token) => as_token,
        Err(e) => {
            return Ok(bad_evidence_response(e));
        }
    };

    let claims: ASCoreTokenClaims = parse_as_token_claims(&as_token)
        .map_err(|e| format!("Error while parsing AS token: {:?}", e))
        .unwrap();

    let response_body = AttestationEvalEvidenceResponse {
        eval: true,
        claims: Some(claims),
    };
    let response_json = serde_json::to_string(&response_body).unwrap();
    Ok(Response::new(Body::from(response_json)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init_coco_as;
    use crate::utils::test_utils::{is_sudo, read_vector_txt};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use hyper::{Body, Request, Response, StatusCode};
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
        let ex_token_path = "../examples/as_token.txt";
        let ex_token = std::fs::read_to_string(ex_token_path).unwrap();

        let claims = parse_as_token_claims(&ex_token).unwrap();

        assert_eq!(claims.tee, "aztdxvtpm");
        let evaluation_reports = serde_json::to_string(&claims.evaluation_reports).unwrap();
        assert_eq!(evaluation_reports, "[{\"policy-hash\":\"61792a819cb38c3bda3026ddcc0300685e01bfb9e77eee0122af0064cd4880a6475c9a9fb6001cca2fcaddcea24bb1bf\",\"policy-id\":\"allow_any\"}]");
        assert_eq!(
            claims.tcb_status.get("aztdxvtpm.quote.body.mr_td"),
            Some(&Value::String("bb379f8e734a755832509f61403f99db2258a70a01e1172a499d6d364101b0675455b4e372a35c1f006541f2de0d7154".to_string()))
        );
        assert!(claims.reference_data.is_empty());
        assert_eq!(claims.customized_claims.init_data, Value::Null);
        assert_eq!(claims.customized_claims.runtime_data, Value::Null);
    }

    #[tokio::test]
    async fn test_attestation_eval_evidence_handler_invalid_json() {
        // Create a request with invalid JSON body
        let req = Request::builder()
            .method("POST")
            .uri("/attestation/as/eval_evidence")
            .header("Content-Type", "application/json")
            .body(Body::from("Invalid JSON"))
            .unwrap();

        // Call the handler
        let res: Response<Body> = attestation_eval_evidence_handler(req).await.unwrap();

        // Check that the response status is 400 Bad Request
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // Parse and check the response body
        let body_bytes = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let response_json: Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(response_json["error"], "Invalid JSON in request body");
    }

    #[tokio::test]
    #[serial(attestation_service)]
    async fn test_eval_evidence_sample() {
        // handle set up permissions
        if !is_sudo() {
            eprintln!("test_eval_evidence_sample: skipped (requires sudo privileges)");
            return;
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

        // Serialize the request to JSON
        let payload_json = serde_json::to_string(&eval_request).unwrap();

        // Create a request
        let req = Request::builder()
            .method("POST")
            .uri("/attestation/as/eval_evidence")
            .header("Content-Type", "application/json")
            .body(Body::from(payload_json))
            .unwrap();

        // Call the handler
        let res: Response<Body> = attestation_eval_evidence_handler(req).await.unwrap();

        // Check that the response status is 200 OK
        assert_eq!(res.status(), StatusCode::OK);

        // Parse and check the response body
        let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let eval_evidence_response: AttestationEvalEvidenceResponse =
            serde_json::from_slice(&body).unwrap();

        assert!(eval_evidence_response.eval);
        let claims = eval_evidence_response.claims.unwrap();
        assert_eq!(claims.tee, "sample");
        assert_eq!(claims.tcb_status["report_data"], "bm9uY2U=");
    }

    #[tokio::test]
    #[serial(attestation_service)]
    async fn test_eval_evidence_az_tdx() {
        // handle set up permissions
        if !is_sudo() {
            eprintln!("test_eval_evidence_az_tdx: skipped (requires sudo privileges)");
            return;
        }

        // Initialize ATTESTATION_SERVICE
        init_coco_as(None)
            .await
            .expect("Failed to initialize AttestationService");

        // Mock a valid AttestationEvalEvidenceRequest
        let tdx_evidence_encoded =
            std::fs::read_to_string("../examples/tdx_encoded_evidence.txt").unwrap();
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

        // Serialize the request to JSON
        let payload_json = serde_json::to_string(&tdx_eval_request).unwrap();

        // Create a request
        let req = Request::builder()
            .method("POST")
            .uri("/attestation/as/eval_evidence")
            .header("Content-Type", "application/json")
            .body(Body::from(payload_json))
            .unwrap();

        // Call the handler
        let res: Response<Body> = attestation_eval_evidence_handler(req).await.unwrap();

        // Check that the response status is 200 OK
        assert_eq!(res.status(), StatusCode::OK);

        // Parse and check the response body
        let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let eval_evidence_response: AttestationEvalEvidenceResponse =
            serde_json::from_slice(&body).unwrap();

        assert!(eval_evidence_response.eval);
        let claims = eval_evidence_response.claims.unwrap();

        assert_eq!(claims.tee, "aztdxvtpm");
        let evaluation_reports = serde_json::to_string(&claims.evaluation_reports).unwrap();
        assert_eq!(evaluation_reports, "[{\"policy-hash\":\"fbb1cf91bb453d7c89b04cbc8d727dc142c47d84c5c9c2012b8c86d4d1892874743a63f7448e592ca6bee9cfeb286732\",\"policy-id\":\"allow\"}]");
        assert_eq!(
            claims.tcb_status.get("aztdxvtpm.quote.body.mr_td"),
            Some(&Value::String("bb379f8e734a755832509f61403f99db2258a70a01e1172a499d6d364101b0675455b4e372a35c1f006541f2de0d7154".to_string()))
        );
        assert!(claims.reference_data.is_empty());
        assert_eq!(claims.customized_claims.init_data, Value::Null);
        assert_eq!(claims.customized_claims.runtime_data, Value::Null);
    }

    #[tokio::test]
    #[serial(attestation_service)]
    async fn test_eval_policy_deny() {
        // handle set up permissions
        if !is_sudo() {
            eprintln!("test_eval_evidence_az_tdx: skipped (requires sudo privileges)");
            return;
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

        // Serialize the request to JSON
        let payload_json = serde_json::to_string(&eval_request).unwrap();

        // Create a request
        let req = Request::builder()
            .method("POST")
            .uri("/attestation/as/eval_evidence")
            .header("Content-Type", "application/json")
            .body(Body::from(payload_json))
            .unwrap();

        // Call the handler
        let res: Response<Body> = attestation_eval_evidence_handler(req).await.unwrap();

        // Check that the response status is 200 OK
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[serial(attestation_service)]
    async fn test_eval_evidence_az_tdx_tpm_pcr04() {
        // handle set up permissions
        if !is_sudo() {
            eprintln!("test_eval_evidence_az_tdx_tpm_pcr04: skipped (requires sudo privileges)");
            return;
        }

        init_coco_as(None)
            .await
            .expect("Failed to initialize AttestationService");

        // Make a passing request to validate using a policy that checks mr_td, mr_seam, and pcr04
        let az_tdx_evidence: Vec<u8> =
            read_vector_txt("../examples/yocto_20241023223507.txt".to_string()).unwrap();
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

        let payload_json = serde_json::to_string(&tdx_eval_request).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/attestation/as/eval_evidence")
            .header("Content-Type", "application/json")
            .body(Body::from(payload_json))
            .unwrap();

        let res: Response<Body> = attestation_eval_evidence_handler(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{res:?}");

        // Make a failing request to validate using a policy that checks mr_td, mr_seam, and pcr04
        let az_tdx_evidence: Vec<u8> =
            read_vector_txt("../examples/yocto_20241025193121.txt".to_string()).unwrap();
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

        let payload_json = serde_json::to_string(&tdx_eval_request).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/attestation/as/eval_evidence")
            .header("Content-Type", "application/json")
            .body(Body::from(payload_json))
            .unwrap();

        let res: Response<Body> = attestation_eval_evidence_handler(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{res:?}");
        let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("Policy evaluation denied"));
    }
}
