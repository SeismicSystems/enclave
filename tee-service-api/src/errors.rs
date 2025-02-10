use anyhow::Error;
use hyper::{Response, StatusCode};
use serde_json::json;
use crate::request_types::response::BytesBody;

/// Returns 400 Bad Request
/// Meant to be used if there is an error while reading the request body
pub fn invalid_req_body_resp() -> Response<BytesBody> {
    let error_response = json!({ "error": "Invalid request body" }).to_string();
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(BytesBody::from(error_response))
        .unwrap()
}

// Returns 400 Bad Request
// Meant to be used if deserializing the body into a json fails
pub fn invalid_json_body_resp() -> Response<BytesBody> {
    let error_response = json!({ "error": "Invalid JSON in request body" }).to_string();
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(BytesBody::from(error_response))
        .unwrap()
}

/// Returns a 400 Bad Request response with the error message
/// describing why the evaluation failed,
/// Ex the evidence is invalid, doesn't match the request policy, etc
pub fn bad_evidence_response(e: anyhow::Error) -> Response<BytesBody> {
    let error_message = format!("Error while evaluating evidence: {:?}", e);
    let error_response = json!({ "error": error_message }).to_string();

    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(BytesBody::from(error_response))
        .unwrap()
}

/// Returns a 400 Bad Request response with the error message
/// explaining why the arugment is invalid.
pub fn bad_argument_response(e: anyhow::Error) -> Response<BytesBody> {
    let error_message = format!("Invalid Argument: {:?}", e);
    let error_response = json!({ "error": error_message }).to_string();

    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(BytesBody::from(error_response))
        .unwrap()
}

// Returns 422 Unprocessable Entity
// Meant to be used if decrypting the ciphertext fails
pub fn invalid_ciphertext_resp(e: Error) -> Response<BytesBody> {
    let error_message = format!("Invalid ciphertext: {}", e); // Use error's Display trait
    let error_response = json!({ "error": error_message }).to_string();

    Response::builder()
        .status(StatusCode::UNPROCESSABLE_ENTITY)
        .body(BytesBody::from(error_response))
        .unwrap()
}
