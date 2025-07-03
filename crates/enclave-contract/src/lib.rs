//! Enclave Contract - Utilities for deploying and interacting with smart contracts
//!
//! This crate provides utilities for deploying smart contracts using both regular
//! deployment and CREATE2 deployment through factory contracts.

#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod contract_interface;
pub mod deployment;

pub use contract_interface::*;
pub use deployment::*;
