use hyper::body::to_bytes;
use hyper::{Body, Request, Response};
use secp256k1::ecdh::SharedSecret;
use secp256k1::SecretKey;
use std::convert::Infallible;

use crate::tx_io::structs::*;
use crate::tx_io::utils::*;

pub async fn tx_io_encrypt_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    // parse the request body
    let body_bytes = to_bytes(req.into_body()).await.unwrap();
    let encryption_request: IoEncryptionRequest = serde_json::from_slice(&body_bytes).unwrap();

    // load key and encrypt data
    let ecdh_sk = get_secp256k1_sk();
    let shared_secret = SharedSecret::new(&encryption_request.msg_sender, &ecdh_sk);
    let aes_key = derive_aes_key(&shared_secret).unwrap();
    let encrypted_data = aes_encrypt(&aes_key, &encryption_request.data, encryption_request.nonce);

    // response
    let response_body = IoEncryptionResponse { encrypted_data };
    let response_json = serde_json::to_string(&response_body).unwrap();

    Ok(Response::new(Body::from(response_json)))
}

pub async fn tx_io_decrypt_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    // parse the request body
    let body_bytes = to_bytes(req.into_body()).await.unwrap();
    let decryption_request: IoDecryptionRequest = serde_json::from_slice(&body_bytes).unwrap();

    // load key and decrypt data
    let ecdh_sk = get_secp256k1_sk();
    let shared_secret = SharedSecret::new(&decryption_request.msg_sender, &ecdh_sk);
    let aes_key = derive_aes_key(&shared_secret).unwrap();
    let decrypted_data = aes_decrypt(&aes_key, &decryption_request.data, decryption_request.nonce);

    // response
    let response_body = IoDecryptionResponse {
        decrypted_data: decrypted_data,
    };
    let response_json = serde_json::to_string(&response_body).unwrap();

    Ok(Response::new(Body::from(response_json)))
}

// temporary function for testing that reads the keypair from a file
// should eventually make a request to a kms service
fn get_secp256k1_sk() -> SecretKey {
    let ecdh_sk = read_secp256k1_keypair("./src/tx_io/ex_keypair.json")
        .unwrap()
        .secret_key;

    ecdh_sk
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{Body, Request};
    use secp256k1::PublicKey;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_io_encryptin() {
        // Prepare encryption request body
        let base_url = "http://localhost:7878";
        let data_to_encrypt = vec![72, 101, 108, 108, 111];
        let encryption_request = IoEncryptionRequest {
            msg_sender: PublicKey::from_str(
                "03e31e68908a6404a128904579c677534d19d0e5db80c7d9cf4de6b4b7fe0518bd",
            )
            .unwrap(),
            data: data_to_encrypt.clone(),
            nonce: 12345678,
        };
        let payload_json = serde_json::to_string(&encryption_request).unwrap();

        let req = Request::builder()
            .method("POST")
            .uri(format!("{}/io_encrypt", base_url))
            .header("Content-Type", "application/json")
            .body(Body::from(payload_json))
            .unwrap();

        let res = tx_io_encrypt_handler(req).await.unwrap();
        assert_eq!(res.status(), 200);

        // Parse the response body
        let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
        println!("body: {:?}", body);
        let enc_response: IoEncryptionResponse = serde_json::from_slice(&body).unwrap();
        assert!(!enc_response.encrypted_data.is_empty());

        // check that decryption returns the original data
        // Prepare decrypt request body
        let decryption_request = IoDecryptionRequest {
            msg_sender: PublicKey::from_str(
                "03e31e68908a6404a128904579c677534d19d0e5db80c7d9cf4de6b4b7fe0518bd",
            )
            .unwrap(),
            data: enc_response.encrypted_data,
            nonce: 12345678,
        };
        let payload_json = serde_json::to_string(&decryption_request).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri(format!("{}/io_decrypt", base_url))
            .header("Content-Type", "application/json")
            .body(Body::from(payload_json))
            .unwrap();

        let res = tx_io_decrypt_handler(req).await.unwrap();
        assert_eq!(res.status(), 200);

        let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let dec_response: IoDecryptionResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(dec_response.decrypted_data, data_to_encrypt);
    }
}
