use attestation_service::HashAlgorithm;
use hyper::{body::to_bytes, Body, Request, Response, StatusCode};
use serde_json::json;
use std::convert::Infallible;

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
    let coco_as = ATTESTATION_SERVICE.get().unwrap();
    let evaluate_response = coco_as
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

    // Return the evaluation result as a response
    let response_json = serde_json::to_string(&evaluate_response).unwrap();
    Ok(Response::new(Body::from(response_json)))
}