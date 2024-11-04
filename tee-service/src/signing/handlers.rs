use hyper::{body::to_bytes, Body, Request, Response, StatusCode};
use serde_json::json;
use std::convert::Infallible;

use tee_service_api::request_types::signing::*;
use crate::utils::crypto_utils::*;
use crate::utils::response_utils::{invalid_json_body_resp, invalid_req_body_resp};

/// Handles request to sign a message using secp256k1.
///
/// # Arguments
/// * `req` - The incoming HTTP request containing the message to be signed. The body of the request
///   Should be a JSON-encoded `Secp256k1SignRequest`.
///
/// # Returns
/// A `Result` containing an HTTP response with the signature, or an error of type `Infallible`.
/// The response body is JSON-encoded and contains the signature as part of a `Secp256k1SignResponse`.
///
/// # Errors
/// The function may panic if parsing the request body or signing the message fails.
pub async fn secp256k1_sign_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    // parse the request body
    let body_bytes = match to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(invalid_req_body_resp());
        }
    };

    // deserialize the request body
    let sign_request: Secp256k1SignRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => {
            return Ok(invalid_json_body_resp());
        }
    };

    // sign the message
    let sk = get_secp256k1_sk();
    let signature = secp256k1_sign_digest(&sign_request.msg, sk)
        .expect("Internal Error while signing the message");

    let response_body = Secp256k1SignResponse { sig: signature };
    let response_json = serde_json::to_string(&response_body).unwrap();

    Ok(Response::new(Body::from(response_json)))
}

/// Handles request to verify a secp256k1 signature.
///
/// # Arguments
/// * `req` - The incoming HTTP request containing the message and signature to verify. The body of the request
///   Should be a JSON-encoded `Secp256k1VerifyRequest`.
///
/// # Returns
/// A `Result` containing an HTTP response with the verification result, or an error of type `Infallible`.
/// The response body is JSON-encoded and contains the verification result as part of a `Secp256k1VerifyResponse`.
///
/// # Errors
/// The function may panic if parsing the request body or verifying the signature fails.
pub async fn secp256k1_verify_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    // parse the request body
    // parse the request body
    let body_bytes = match to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(_) => {
            // Return 400 Bad Request if there is an error while reading the body
            let error_response = json!({ "error": "Invalid request body" }).to_string();
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(error_response))
                .unwrap());
        }
    };

    // deserialize the request body
    let verify_request: Secp256k1VerifyRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => {
            return Ok(invalid_json_body_resp());
        }
    };

    // verify the signature
    let pk = get_secp256k1_pk();
    let verified = secp256k1_verify(&verify_request.msg, &verify_request.sig, pk)
        .expect("Internal error while verifying the signature");

    let response_body = Secp256k1VerifyResponse { verified };
    let response_json = serde_json::to_string(&response_body).unwrap();

    Ok(Response::new(Body::from(response_json)))
}

/// Loads a secp256k1 private key from a file.
///
/// This function reads the keypair from a JSON file for testing purposes. Eventually, it should
/// be replaced with a more secure solution, such as requesting a key from a KMS service.
///
/// # Returns
/// A secp256k1 `SecretKey` loaded from the keypair file.
///
/// # Panics
/// The function may panic if the file is missing or if it cannot deserialize the keypair.
fn get_secp256k1_sk() -> secp256k1::SecretKey {
    get_sample_secp256k1_sk()
}

/// Loads a secp256k1 public key from a file.
///
/// This function reads the keypair from a JSON file for testing purposes. Eventually, it should
/// be replaced with a more secure solution, such as requesting a key from a KMS service.
///
/// # Returns
/// A secp256k1 `PublicKey` loaded from the keypair file.
///
/// # Panics
/// The function may panic if the file is missing or if it cannot deserialize the keypair.
fn get_secp256k1_pk() -> secp256k1::PublicKey {
    get_sample_secp256k1_pk()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{Body, Request};

    #[tokio::test]
    async fn test_secp256k1_sign() {
        // Prepare sign request body
        let msg_to_sign: Vec<u8> = vec![84, 101, 115, 116, 32, 77, 101, 115, 115, 97, 103, 101]; // "Test Message"
        let sign_request = Secp256k1SignRequest {
            msg: msg_to_sign.clone(),
        };
        let payload_json = serde_json::to_string(&sign_request).unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/sign")
            .header("Content-Type", "application/json")
            .body(Body::from(payload_json))
            .unwrap();

        let res = secp256k1_sign_handler(req).await.unwrap();
        assert_eq!(res.status(), 200);

        // Parse the response body
        let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let sign_response: Secp256k1SignResponse = serde_json::from_slice(&body).unwrap();
        assert!(!sign_response.sig.is_empty());
    }

    #[tokio::test]
    async fn test_secp256k1_sign_invalid_body() {
        // Prepare invalid request body (non-JSON body)
        let req = Request::builder()
            .method("POST")
            .uri("/sign")
            .header("Content-Type", "application/json")
            .body(Body::from("invalid body"))
            .unwrap();

        let res = secp256k1_sign_handler(req).await.unwrap();
        assert_eq!(res.status(), 400);

        // Parse the response body
        let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let error_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response["error"], "Invalid JSON in request body");
    }

    #[tokio::test]
    async fn test_secp256k1_verify() {
        // Prepare sign request to get a valid signature
        let msg_to_sign: Vec<u8> = vec![84, 101, 115, 116, 32, 77, 101, 115, 115, 97, 103, 101]; // "Test Message"
        let sign_request = Secp256k1SignRequest {
            msg: msg_to_sign.clone(),
        };
        let sign_payload_json = serde_json::to_string(&sign_request).unwrap();

        let sign_req = Request::builder()
            .method("POST")
            .uri("/sign")
            .header("Content-Type", "application/json")
            .body(Body::from(sign_payload_json))
            .unwrap();

        let sign_res = secp256k1_sign_handler(sign_req).await.unwrap();
        let sign_body = hyper::body::to_bytes(sign_res.into_body()).await.unwrap();
        let sign_response: Secp256k1SignResponse = serde_json::from_slice(&sign_body).unwrap();

        // Prepare verify request body
        let verify_request = Secp256k1VerifyRequest {
            msg: msg_to_sign,
            sig: sign_response.sig,
        };
        let verify_payload_json = serde_json::to_string(&verify_request).unwrap();

        let verify_req = Request::builder()
            .method("POST")
            .uri("/verify")
            .header("Content-Type", "application/json")
            .body(Body::from(verify_payload_json))
            .unwrap();

        let verify_res = secp256k1_verify_handler(verify_req).await.unwrap();
        assert_eq!(verify_res.status(), 200);

        // Parse the response body
        let verify_body = hyper::body::to_bytes(verify_res.into_body()).await.unwrap();
        let verify_response: Secp256k1VerifyResponse =
            serde_json::from_slice(&verify_body).unwrap();
        assert!(verify_response.verified);
    }

    #[tokio::test]
    async fn test_secp256k1_verify_invalid_body() {
        // Prepare invalid request body (non-JSON body)
        let req = Request::builder()
            .method("POST")
            .uri("/verify")
            .header("Content-Type", "application/json")
            .body(Body::from("invalid body"))
            .unwrap();

        let res = secp256k1_verify_handler(req).await.unwrap();
        assert_eq!(res.status(), 400);

        // Parse the response body
        let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let error_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response["error"], "Invalid JSON in request body");
    }
}
