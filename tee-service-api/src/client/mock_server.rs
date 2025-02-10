use anyhow::Result;

use crate::request_types::response::{string_body, BytesBody};
use hyper::{body::Incoming, Request, Response};
use std::convert::Infallible;

pub trait MockServer {
    fn attestation_get_evidence_handler(
        &self,
        _req: Request<Incoming>,
    ) -> Result<Response<BytesBody>, Infallible> {
        let body = string_body("Error: Mock Unimplimented".to_string());
        Ok(Response::builder().status(500).body(body).unwrap())
    }

    fn attestation_eval_evidence_handler(
        &self,
        _req: Request<Incoming>,
    ) -> Result<Response<BytesBody>, Infallible> {
        let body = string_body("Error: Mock Unimplimented".to_string());
        Ok(Response::builder().status(500).body(body).unwrap())
    }

    fn genesis_get_data_handler(
        &self,
        _req: Request<Incoming>,
    ) -> Result<Response<BytesBody>, Infallible> {
        let body = string_body("Error: Mock Unimplimented".to_string());
        Ok(Response::builder().status(500).body(body).unwrap())
    }

    fn secp256k1_sign_handler(
        &self,
        _req: Request<Incoming>,
    ) -> Result<Response<BytesBody>, Infallible> {
        let body = string_body("Error: Mock Unimplimented".to_string());
        Ok(Response::builder().status(500).body(body).unwrap())
    }

    fn secp256k1_verify_handler(
        &self,
        _req: Request<Incoming>,
    ) -> Result<Response<BytesBody>, Infallible> {
        let body = string_body("Error: Mock Unimplimented".to_string());
        Ok(Response::builder().status(500).body(body).unwrap())
    }

    fn tx_io_encrypt_handler(
        &self,
        _req: Request<Incoming>,
    ) -> Result<Response<BytesBody>, Infallible> {
        let body = string_body("Error: Mock Unimplimented".to_string());
        Ok(Response::builder().status(500).body(body).unwrap())
    }

    fn tx_io_decrypt_handler(
        &self,
        _req: Request<Incoming>,
    ) -> Result<Response<BytesBody>, Infallible> {
        let body = string_body("Error: Mock Unimplimented".to_string());
        Ok(Response::builder().status(500).body(body).unwrap())
    }
    fn get_eph_rng_keypair(&self) -> Result<Response<BytesBody>, Infallible> {
        let body = string_body("Error: Mock Unimplimented".to_string());
        Ok(Response::builder().status(500).body(body).unwrap())
    }
}
