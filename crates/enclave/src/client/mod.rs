//! This module provides a client for interacting with a TEE Service server.
//!
//! The TEE client makes HTTP requests to a TEE server to perform
//! operations, e.g. encryption and decryption operations. The main structures and
//! traits define the API and implementation for the TEE client.
#![allow(async_fn_in_trait)]
pub mod client;
pub mod mock;
pub mod rpc;
pub (crate) mod booter;

pub use client::*;
pub use mock::*;
pub use booter::{boot_enclave, BootError};
