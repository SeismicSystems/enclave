//! This module provides a client for interacting with a TEE Service server.
//!
//! The TEE client makes HTTP requests to a TEE server to perform
//! operations, e.g. encryption and decryption operations. The main structures and
//! traits define the API and implementation for the TEE client.
#![allow(async_fn_in_trait)]
pub mod mock_server;
pub mod rpc;

use crate::nonce::Nonce;

pub trait WalletAPI {
    fn encrypt(
        &self,
        data: Vec<u8>,
        nonce: impl Into<Nonce>,
        private_key: &secp256k1::SecretKey,
    ) -> Result<Vec<u8>, anyhow::Error>;

    fn decrypt(
        &self,
        data: Vec<u8>,
        nonce: impl Into<Nonce>,
        private_key: &secp256k1::SecretKey,
    ) -> Result<Vec<u8>, anyhow::Error>;
}
