//! The enclave's minimal, read-only interface to the canonical on-chain
//! `MeasurementRegistry`.
//!
//! Measurement schemas, admission-ID derivation, and genesis storage derivation
//! live in `seismic-measurement-admission`. Contract mutation and admin-key
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

#[cfg(test)]
mod tests {
    use super::MeasurementRegistry::isAcceptedCall;
    use alloy_sol_types::SolCall;

    /// The seismic repo holds this binding to its canonical contract artifact
    /// at the rev that pins this crate; this pins it locally.
    #[test]
    fn runtime_read_selector_is_pinned() {
        assert_eq!(isAcceptedCall::SIGNATURE, "isAccepted(bytes32)");
        assert_eq!(isAcceptedCall::SELECTOR, [0xa7, 0x8f, 0x84, 0xcf]);
    }
}
