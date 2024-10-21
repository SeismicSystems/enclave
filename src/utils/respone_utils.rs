use hyper::{Body, Response, StatusCode};
use serde_json::json;

/// Returns 400 Bad Request
/// Meant to be used if there is an error while reading the request body
pub fn invalid_req_body_resp() -> Response<Body> {
    let error_response = json!({ "error": "Invalid request body" }).to_string();
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::from(error_response))
        .unwrap()
}

// Returns 400 Bad Request
// Meant to be used if deserializing the body into a json fails
pub fn invalid_json_body_resp() -> Response<Body> {
    let error_response = json!({ "error": "Invalid JSON in request body" }).to_string();
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::from(error_response))
        .unwrap()
}
