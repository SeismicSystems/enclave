use hyper::{body::to_bytes, Body, Request, Response, StatusCode};
use serde_json::json;
use tokio::signal;
use std::convert::Infallible;

use tee_service_api::errors::{invalid_json_body_resp, invalid_req_body_resp};
use tee_service_api::request_types::snapsync::*;

pub async fn snapsync_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
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
    todo!("verify attestation");

    // extract the request encryption key
    let req_enc_key = todo!("extract encryption key");

    // actually get the SnapSync data
    let response_body: SnapSyncResponse = build_snapsync_response(req_enc_key);
    

    // return the response
    let response_json = serde_json::to_string(&response_body).unwrap();
    Ok(Response::new(Body::from(response_json)))
}

fn build_snapsync_response() -> SnapSyncResponse {
    let attestation = attest_to_signing_key();
    let snapsync_data = gather_snapsync_data();
    let signature = sign_snapsync_data();
    SnapSyncResponse {
        server_attestation: attestation,
        snapsync_data,
        signature,
    }
}