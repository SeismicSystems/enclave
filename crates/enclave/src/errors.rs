use anyhow::Error;
use http_body_util::Full;
use hyper::{body::Bytes, header::CONTENT_TYPE, Response, StatusCode};
use jsonrpsee::core::RpcResult;
use serde_json::json;

/// Returns 400 Bad Request
/// Meant to be used if there is an error while reading the request body
pub fn invalid_req_body_resp() -> Response<Full<Bytes>> {
    let error_response = json!({ "error": "Invalid request body" }).to_string();
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(error_response)))
        .unwrap()
}

// Returns 400 Bad Request
// Meant to be used if deserializing the body into a json fails
pub fn invalid_json_body_resp() -> Response<Full<Bytes>> {
    let error_response = json!({ "error": "Invalid JSON in request body" }).to_string();
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(error_response)))
        .unwrap()
}

/// Returns a 400 Bad Request response with an error message describing
/// why the evaluation failed.
pub fn bad_evidence_response(e: Error) -> Response<Full<Bytes>> {
    let error_message = format!("Error while evaluating evidence: {:?}", e);
    let error_response = json!({ "error": error_message }).to_string();

    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(error_response)))
        .unwrap()
}

/// Returns a 400 Bad Request response with an error message explaining
/// why the argument is invalid.
pub fn bad_argument_response(e: Error) -> Response<Full<Bytes>> {
    let error_message = format!("Invalid Argument: {:?}", e);
    let error_response = json!({ "error": error_message }).to_string();

    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(error_response)))
        .unwrap()
}

// Returns 422 Unprocessable Entity, used if decrypting the ciphertext fails
pub fn invalid_ciphertext_resp(e: Error) -> Response<Full<Bytes>> {
    let error_message = format!("Invalid ciphertext: {}", e);
    let error_response = json!({ "error": error_message }).to_string();

    Response::builder()
        .status(StatusCode::UNPROCESSABLE_ENTITY)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(error_response)))
        .unwrap()
}

/// Convert a bad evidence error into a JSON-RPC error response
pub fn rpc_bad_evidence_error(e: Error) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObject::owned(
        jsonrpsee::types::error::INVALID_PARAMS_CODE,
        format!("Error while evaluating evidence: {:?}", e),
        None::<()>,
    )
}

/// Convert a bad argument error into a JSON-RPC error response
pub fn rpc_bad_argument_error(e: Error) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObject::owned(
        jsonrpsee::types::error::INVALID_PARAMS_CODE,
        format!("Invalid Argument: {:?}", e),
        None::<()>,
    )
}

/// Convert an invalid ciphertext error into a JSON-RPC error response
pub fn rpc_invalid_ciphertext_error(e: Error) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObject::owned(
        jsonrpsee::types::error::INVALID_PARAMS_CODE,
        format!("Invalid ciphertext: {}", e),
        None::<()>,
    )
}
