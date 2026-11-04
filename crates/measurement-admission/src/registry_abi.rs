//! The full protocol interface of the canonical `MeasurementRegistry`
//! contract
//! (https://github.com/SeismicSystems/seismic/blob/main/contracts/src/predeploys/MeasurementRegistry.sol),
//! behind the `registry-abi` feature.
//!
//! The interface lives beside [`REGISTRY_RUNTIME_CODE_HASH`] and the storage
//! layout in [`crate::genesis`] because all three describe the same contract
//! build. The seismic repo owns that build: it pins this crate and holds this
//! interface's selectors, and the runtime-code hash, to its committed
//! artifact. This repo never reads the artifact, so a contract change is
//! checked once, where the artifact lives, at the rev that pins this crate.
//!
//! Enclave *runtime* code reaches the registry through
//! `seismic-measurement-registry-client`'s narrow read-only binding instead.
//!
//! [`REGISTRY_RUNTIME_CODE_HASH`]: crate::genesis::REGISTRY_RUNTIME_CODE_HASH

use alloy_sol_types::sol;

sol! {
    /// The registry's full external surface: its reads and the admin's two
    /// mutations.
    #[sol(rpc)]
    interface IMeasurementRegistry {
        function admin() external view returns (address);
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
        function transferAdmin(address newAdmin) external;
    }
}

#[cfg(test)]
mod tests {
    use super::IMeasurementRegistry::IMeasurementRegistryCalls;

    /// Editing the interface is a protocol change: it must also change this
    /// list, and then the seismic repo's parity check at the next pin bump.
    #[test]
    fn interface_signatures_are_pinned() {
        let mut declared = IMeasurementRegistryCalls::SIGNATURES.to_vec();
        declared.sort_unstable();
        assert_eq!(
            declared,
            [
                "acceptedCount()",
                "activePolicyHash()",
                "admin()",
                "applyPolicyUpdate(bytes32[],bytes32[],bytes32)",
                "bootstrapPolicyHash()",
                "isAccepted(bytes32)",
                "policyRevision()",
                "statusOf(bytes32)",
                "transferAdmin(address)",
            ]
        );
    }
}
