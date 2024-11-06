use hyper::{body::to_bytes, Body, Request, Response};
use std::convert::Infallible;
use attestation_service::HashAlgorithm;

use tee_service_api::errors::{invalid_json_body_resp, invalid_req_body_resp, bad_evidence_response};
use tee_service_api::request_types::snapsync::*;
use tee_service_api::coco_as::ASCoreTokenClaims;
use crate::coco_as::{eval_att_evidence, parse_as_token_claims};

pub async fn provide_snapsync_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    // parse the request body
    let body_bytes = match to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(invalid_req_body_resp());
        }
    };

    // Deserialize the request body into the appropriate struct
    let snapsync_request: SnapSyncRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => {
            return Ok(invalid_json_body_resp());
        }
    };

    // verify the request attestation
    let eval_result = eval_att_evidence(
        snapsync_request.client_attestation,
        snapsync_request.tee,
        Some(attestation_service::Data::Raw(snapsync_request.rsa_pk_pem)),
        HashAlgorithm::Sha256,
        None,
        HashAlgorithm::Sha256,
        snapsync_request.policy_ids,
    ).await;

    let as_token: String = match eval_result {
        Ok(as_token) => as_token,
        Err(e) => {
            return Ok(bad_evidence_response(e));
        }
    };

    let claims: ASCoreTokenClaims = parse_as_token_claims(&as_token)
        .map_err(|e| format!("Error while parsing AS token: {:?}", e))
        .unwrap();

    println!("claims: {:?}", claims);
    // extract the request encryption key
    let req_enc_key = todo!("extract encryption key");

    // // actually get the SnapSync data
    // let response_body: SnapSyncResponse = build_snapsync_response(req_enc_key);
    

    // return the response
    let response_json = serde_json::to_string("&response_body").unwrap();
    // let response_json = serde_json::to_string(&response_body).unwrap();
    Ok(Response::new(Body::from(response_json)))
}

