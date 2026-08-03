//! Shared `sol!` bindings for the registry test suites.
//!
//! `IMeasurementRegistry` mirrors the full protocol surface of the canonical
//! `MeasurementRegistry` contract — `registry_abi.rs` holds its selector set
//! equal to the canonical artifact's ABI, so the mutating functions belong here
//! even though only `reth_registry.rs`'s authority path exercises them.
//! Enclave *runtime* code reaches the registry through
//! `seismic-measurement-registry-client`'s narrow read-only binding instead.

#![allow(dead_code)]

use alloy::sol;

sol! {
    #[sol(rpc)]
    interface IMeasurementRegistry {
        function AUTHORITY() external view returns (address);
        function isAccepted(bytes32 admissionId) external view returns (bool);
        function statusOf(bytes32 admissionId) external view returns (uint8);
        function bootstrapPolicyHash() external view returns (bytes32);
        function activePolicyHash() external view returns (bytes32);
        function policyRevision() external view returns (uint64);
        function acceptedCount() external view returns (uint256);
        function applyPolicyUpdate(
            bytes32[] calldata accept,
            bytes32[] calldata deprecate,
            bytes32 newActivePolicyHash
        ) external;
    }

    #[sol(rpc)]
    interface IMeasurementAuthorityDev {
        function applyPolicyUpdate(
            bytes32[] calldata accept,
            bytes32[] calldata deprecate,
            bytes32 newActivePolicyHash
        ) external;
    }
}
