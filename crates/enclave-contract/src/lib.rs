//! Enclave Contract - Utilities for deploying and interacting with smart contracts
//!
//! This crate provides utilities for deploying smart contracts using both regular
//! deployment and CREATE2 deployment through factory contracts.

#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod contract_interface;
pub use contract_interface::UpgradeOperator::Measurements;
pub use contract_interface::*;

/// Anvil's first secret key that they publically expose and fund for testing
pub const ANVIL_ALICE_SK: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

pub const ANVIL_BOB_SK: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

pub const ANVIL_CHARLIE_SK: &str =
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

/// The address of the UpgradeOperator contract
/// seismic-reth deploys this code at genesis
pub const UPGRADE_OPERATOR_ADDRESS: &str = "0x1000000000000000000000000000000000000001";

/// The address of the MultisigUpgradeOperator contract
/// which can control state transitions of the UpgradeOperator
/// seismic-reth deploys this code at genesis
pub const UPGRADE_MULTISIG_ADDRESS: &str = "0x1000000000000000000000000000000000000002";
