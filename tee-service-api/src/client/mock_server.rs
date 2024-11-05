use anyhow::Result;
use hyper::{Body, Request, Response};
use std::convert::Infallible;

pub trait MockServer {
    fn attestation_get_evidence_handler(
        &self,
        _req: Request<Body>,
    ) -> Result<Response<Body>, Infallible> {
        let body = Body::from(format!("Error: Mock Unimplimented"));
        Ok(Response::builder().status(500).body(body).unwrap())
    }

    fn attestation_eval_evidence_handler(
        &self,
        _req: Request<Body>,
    ) -> Result<Response<Body>, Infallible> {
        let body = Body::from(format!("Error: Mock Unimplimented"));
        Ok(Response::builder().status(500).body(body).unwrap())
    }

    fn genesis_get_data_handler(&self, _req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let body = Body::from(format!("Error: Mock Unimplimented"));
        Ok(Response::builder().status(500).body(body).unwrap())
    }

    fn secp256k1_sign_handler(&self, _req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let body = Body::from(format!("Error: Mock Unimplimented"));
        Ok(Response::builder().status(500).body(body).unwrap())
    }

    fn secp256k1_verify_handler(&self, _req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let body = Body::from(format!("Error: Mock Unimplimented"));
        Ok(Response::builder().status(500).body(body).unwrap())
    }

    fn tx_io_encrypt_handler(&self, _req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let body = Body::from(format!("Error: Mock Unimplimented"));
        Ok(Response::builder().status(500).body(body).unwrap())
    }

    fn tx_io_decrypt_handler(&self, _req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let body = Body::from(format!("Error: Mock Unimplimented"));
        Ok(Response::builder().status(500).body(body).unwrap())
    }
}
