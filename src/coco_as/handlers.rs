use attestation_service::HashAlgorithm;
use hyper::{body::to_bytes, Body, Request, Response, StatusCode};
use serde_json::json;
use std::convert::Infallible;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use crate::ATTESTATION_SERVICE;
use super::structs::*;

pub async fn attestation_eval_evidence_handler(
    req: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    // Parse the request body
    let body_bytes = match to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(_) => {
            let error_response = json!({ "error": "Invalid request body" }).to_string();
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(error_response))
                .unwrap());
        }
    };

    // Deserialize the request body into the evaluate request struct
    let evaluate_request: AttestationEvalEvidenceRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => {
            let error_response = json!({ "error": "Invalid JSON in request body" }).to_string();
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(error_response))
                .unwrap());
        }
    };

    // Call the evaluate function of the attestation service
    // Gets back a b64 JWT web token of the form "header.claims.signature"
    let coco_as = ATTESTATION_SERVICE.get().unwrap();
    let as_token = coco_as
        .evaluate(
            evaluate_request.evidence,
            evaluate_request.tee,
            evaluate_request.runtime_data,
            evaluate_request.runtime_data_hash_algorithm.unwrap(),
            None,
            HashAlgorithm::Sha256, // dummy val to make this compile
            Vec::new(), // replace with the actual policy
        ).await
        .map_err(|e| format!("Error while evaluating evidence: {:?}", e))
        .unwrap();

    let parts: Vec<&str> = as_token.splitn(3, '.').collect();
    let claims_b64 = parts[1];

    // TODO: Decode and parse claims into a respose struct
    let claims_decoded_bytes = URL_SAFE_NO_PAD.decode(&claims_b64).unwrap();
    let claims_decoded_string = String::from_utf8(claims_decoded_bytes).unwrap();
    println!("eval_decoded_string: {:?}", claims_decoded_string);

    let response_json = serde_json::to_string(&claims_decoded_string).unwrap();
    Ok(Response::new(Body::from(response_json)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{Body, Request, Response};
    use serde_json::Value;
    use crate::init_coco_as;
    use kbs_types::Tee;
    use attestation_service::Data;

    #[tokio::test]
    async fn test_attestation_eval_evidence_handler_valid_request() {
        // Initialize ATTESTATION_SERVICE
        init_coco_as().await.expect("Failed to initialize AttestationService");

        // Mock a valid AttestationEvalEvidenceRequest
        let eval_request = AttestationEvalEvidenceRequest {
            evidence: vec![123, 34, 115, 118, 110, 34, 58, 34, 49, 34, 44, 34, 114, 101, 112, 111, 114, 116, 95, 100, 97, 116, 97, 34, 58, 34, 98, 109, 57, 117, 89, 50, 85, 61, 34, 125], // Example evidence data
            tee: Tee::Sample,
            runtime_data: Some(Data::Raw("nonce".as_bytes().to_vec())), // Example runtime data
            runtime_data_hash_algorithm: Some(HashAlgorithm::Sha256),
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
        let body_bytes = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let response_json: Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!("thing", response_json);

        // // Ensure the response includes the expected keys (like result of evaluation)
        // assert!(response_json.get("some_expected_key").is_some());
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
}