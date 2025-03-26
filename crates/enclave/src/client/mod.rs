// //! This module provides a client for interacting with a TEE Service server.
// //!
// //! The TEE client makes HTTP requests to a TEE server to perform
// //! operations, e.g. encryption and decryption operations. The main structures and
// //! traits define the API and implementation for the TEE client.
// #![allow(async_fn_in_trait)]
// pub mod client;
// pub mod mock;
pub mod rpc;

// pub use client::*;
// pub use mock::*;

pub mod client;
pub mod internal;
pub mod operator;
pub mod public;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::OnceLock;
use tokio::runtime::Runtime;

// Endpoints live on different ports based on their security needs
pub const ENCLAVE_DEFAULT_ENDPOINT_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
pub const ENCLAVE_DEFAULT_ENDPOINT_PORT: u16 = 7878;
pub const ENCLAVE_DEFAULT_INTERNAL_PORT: u16 = 7879;
pub const ENCLAVE_DEFAULT_OPERATOR_PORT: u16 = 7880;
pub const ENCLAVE_DEFAULT_PUBLIC_PORT: u16 = 7881;
pub const ENCLAVE_DEFAULT_TIMEOUT_SECONDS: u64 = 5;

pub static ENCLAVE_CLIENT_RUNTIME: OnceLock<Runtime> = OnceLock::new();
