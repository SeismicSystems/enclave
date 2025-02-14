use anyhow::Result;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use std::convert::Infallible;

pub trait MockServer {
    fn attestation_get_evidence_handler(
        &self,
        _req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let body = Full::new(Bytes::from("Error: Mock Unimplimented".to_string()));
        Ok(Response::builder().status(500).body(body).unwrap())
    }

    fn attestation_eval_evidence_handler(
        &self,
        _req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let body = Full::new(Bytes::from("Error: Mock Unimplimented".to_string()));
        Ok(Response::builder().status(500).body(body).unwrap())
    }

    fn genesis_get_data_handler(
        &self,
        _req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let body = Full::new(Bytes::from("Error: Mock Unimplimented".to_string()));
        Ok(Response::builder().status(500).body(body).unwrap())
    }

    fn secp256k1_sign_handler(
        &self,
        _req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let body = Full::new(Bytes::from("Error: Mock Unimplimented".to_string()));
        Ok(Response::builder().status(500).body(body).unwrap())
    }

    fn secp256k1_verify_handler(
        &self,
        _req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let body = Full::new(Bytes::from("Error: Mock Unimplimented".to_string()));
        Ok(Response::builder().status(500).body(body).unwrap())
    }

    fn tx_io_encrypt_handler(
        &self,
        _req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let body = Full::new(Bytes::from("Error: Mock Unimplimented".to_string()));
        Ok(Response::builder().status(500).body(body).unwrap())
    }

    fn tx_io_decrypt_handler(
        &self,
        _req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let body = Full::new(Bytes::from("Error: Mock Unimplimented".to_string()));
        Ok(Response::builder().status(500).body(body).unwrap())
    }
    
    fn get_eph_rng_keypair(&self) -> Result<Response<Full<Bytes>>, Infallible> {
        let body = Full::new(Bytes::from("Error: Mock Unimplimented".to_string()));
        Ok(Response::builder().status(500).body(body).unwrap())
    }
}
