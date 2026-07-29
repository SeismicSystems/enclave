//! The enclave's minimal, read-only interface to the canonical on-chain
//! `MeasurementRegistry`.
//!
//! Measurement schemas, admission-ID derivation, and genesis storage derivation
//! live in `seismic-measurement-admission`. Contract mutation and authority-key
//! handling belong to deployment and governance tooling, not enclave runtime
//! code.

#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use alloy_primitives::{Address, address};
use alloy_sol_types::sol;

/// Address of the canonical `MeasurementRegistry` genesis predeploy.
pub const MEASUREMENT_REGISTRY_ADDRESS: Address =
    address!("0x1000000000000000000000000000000000000001");

sol! {
    /// Runtime policy-consumer interface. The enclave only asks whether a
    /// previously derived admission ID is currently accepted.
    #[sol(rpc)]
    interface MeasurementRegistry {
        function isAccepted(bytes32 admissionId) external view returns (bool);
    }
}
