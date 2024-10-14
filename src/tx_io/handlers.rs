use hyper::{Body, Request, Response};
use hyper::body::to_bytes;
use secp256k1::ecdh::SharedSecret;
use std::convert::Infallible;

use crate::tx_io::structs::*;
use crate::tx_io::utils::*;

pub async fn tx_io_encrypt_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    // parse the request body
    let body_bytes = to_bytes(req.into_body()).await.unwrap();
    let encryption_request: IoEncryptionRequest = serde_json::from_slice(&body_bytes).unwrap();
    
    // load key and encrypt data
    let ecdh_sk = read_secp256k1_keypair("./src/encryption/my_secp256k1/keypair.json").unwrap().secret_key;
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
    let ecdh_sk = read_secp256k1_keypair("./src/encryption/my_secp256k1/keypair.json").unwrap().secret_key;
    let shared_secret = SharedSecret::new(&decryption_request.msg_sender, &ecdh_sk);
    let aes_key = derive_aes_key(&shared_secret).unwrap();
    let decrypted_data = aes_decrypt(&aes_key, &decryption_request.data, decryption_request.nonce);
    
    // response
    let response_body = IoDecryptionResponse { decrypted_data: decrypted_data };
    let response_json = serde_json::to_string(&response_body).unwrap();
    
    Ok(Response::new(Body::from(response_json)))
}