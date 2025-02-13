use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Body, Bytes},
    Request, Response,
};
use std::convert::Infallible;

use super::{enclave_sign, get_secp256k1_pk};
use seismic_enclave::crypto::*;
use seismic_enclave::errors::{invalid_json_body_resp, invalid_req_body_resp};
use seismic_enclave::request_types::signing::*;

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
pub async fn secp256k1_sign_handler(
    req: Request<impl Body>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // parse the request body
    let body_bytes: Bytes = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return Ok(invalid_req_body_resp()),
    };

    // deserialize the request body
    let sign_request: Secp256k1SignRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => {
            return Ok(invalid_json_body_resp());
        }
    };

    // sign the message
    let signature = enclave_sign(&sign_request.msg).unwrap();

    let response_body = Secp256k1SignResponse { sig: signature };
    let response_json = serde_json::to_string(&response_body).unwrap();

    Ok(Response::new(Full::new(Bytes::from(response_json))))
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
pub async fn secp256k1_verify_handler(
    req: Request<impl Body>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // parse the request body
    let body_bytes: Bytes = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return Ok(invalid_req_body_resp()),
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

    Ok(Response::new(Full::new(Bytes::from(response_json))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Request;

    #[tokio::test]
    async fn test_secp256k1_sign() {
        // Prepare sign request body
        let msg_to_sign: Vec<u8> = vec![84, 101, 115, 116, 32, 77, 101, 115, 115, 97, 103, 101]; // "Test Message"
        let sign_request = Secp256k1SignRequest {
            msg: msg_to_sign.clone(),
        };
        let payload_json = serde_json::to_string(&sign_request).unwrap();

        let req: Request<Full<Bytes>> = Request::builder()
            .method("POST")
            .uri("/sign")
            .header("Content-Type", "application/json")
            .body(Full::from(Bytes::from(payload_json)))
            .unwrap();

        let res = secp256k1_sign_handler(req).await.unwrap();
        assert_eq!(res.status(), 200);

        // Parse the response body
        let body: Bytes = res.into_body().collect().await.unwrap().to_bytes();
        let sign_response: Secp256k1SignResponse = serde_json::from_slice(&body).unwrap();
        assert!(!sign_response.sig.is_empty());
    }

    #[tokio::test]
    async fn test_secp256k1_sign_invalid_body() {
        // Prepare invalid request body (non-JSON body)
        let req: Request<Full<Bytes>> = Request::builder()
            .method("POST")
            .uri("/sign")
            .header("Content-Type", "application/json")
            .body(Full::from(Bytes::from("Invalid body")))
            .unwrap();

        let res = secp256k1_sign_handler(req).await.unwrap();
        assert_eq!(res.status(), 400);

        // Parse the response body
        let body: Bytes = res.into_body().collect().await.unwrap().to_bytes();
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

        let sign_req: Request<Full<Bytes>> = Request::builder()
            .method("POST")
            .uri("/sign")
            .header("Content-Type", "application/json")
            .body(Full::from(Bytes::from(sign_payload_json)))
            .unwrap();

        let res = secp256k1_sign_handler(sign_req).await.unwrap();
        let body: Bytes = res.into_body().collect().await.unwrap().to_bytes();
        let sign_response: Secp256k1SignResponse = serde_json::from_slice(&body).unwrap();

        // Prepare verify request body
        let verify_request = Secp256k1VerifyRequest {
            msg: msg_to_sign,
            sig: sign_response.sig,
        };
        let verify_payload_json = serde_json::to_string(&verify_request).unwrap();

        let verify_req: Request<Full<Bytes>> = Request::builder()
            .method("POST")
            .uri("/verify")
            .header("Content-Type", "application/json")
            .body(Full::from(Bytes::from(verify_payload_json)))
            .unwrap();

        let res = secp256k1_verify_handler(verify_req).await.unwrap();
        assert_eq!(res.status(), 200);

        // Parse the response body
        let body: Bytes = res.into_body().collect().await.unwrap().to_bytes();
        let verify_response: Secp256k1VerifyResponse = serde_json::from_slice(&body).unwrap();
        assert!(verify_response.verified);
    }

    #[tokio::test]
    async fn test_secp256k1_verify_invalid_body() {
        // Prepare invalid request body (non-JSON body)
        let req: Request<Full<Bytes>> = Request::builder()
            .method("POST")
            .uri("/verify")
            .header("Content-Type", "application/json")
            .body(Full::from(Bytes::from("Invalid body")))
            .unwrap();

        let res = secp256k1_verify_handler(req).await.unwrap();
        assert_eq!(res.status(), 400);

        // Parse the response body
        let body: Bytes = res.into_body().collect().await.unwrap().to_bytes();
        let error_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error_response["error"], "Invalid JSON in request body");
    }
}
