//! Registry genesis-storage derivation, frozen against the canonical
//! `MeasurementRegistry.sol` layout, see:
//! https://github.com/SeismicSystems/seismic/blob/main/contracts/src/enclave/MeasurementRegistry.sol
//!
//! The registry is a genesis predeploy — its runtime (deployed) bytecode is
//! installed directly into the genesis account, so no constructor ever
//! runs: network-specific policy state is written directly into genesis
//! storage. The layout is the EIP-7201 namespace
//! `seismic.storage.MeasurementRegistry`; the slot constants and formulas
//! here are pinned by golden tests on both sides (Rust here, Solidity in
//! `MeasurementRegistry.t.sol`) and must never change.

use crate::CompiledPolicy;
use alloy_primitives::{B256, U256, b256, keccak256};
use std::collections::BTreeMap;

/// EIP-7201 base slot:
/// `keccak256(abi.encode(uint256(keccak256("seismic.storage.MeasurementRegistry")) - 1)) & ~0xff`.
pub const REGISTRY_STORAGE_LOCATION: B256 =
    b256!("0xa3ae60943e4f183142036d77b94858085814dd428f131289aea7e42703fb0b00");

/// `bootstrapPolicyHash` slot (base + 1): SHA-256 of the exact bootstrap
/// policy document, written at genesis and never changed.
pub const BOOTSTRAP_POLICY_HASH_SLOT: B256 =
    b256!("0xa3ae60943e4f183142036d77b94858085814dd428f131289aea7e42703fb0b01");

/// `activePolicyHash` slot (base + 2): equals `bootstrapPolicyHash` at
/// genesis, replaced atomically by later policy updates.
pub const ACTIVE_POLICY_HASH_SLOT: B256 =
    b256!("0xa3ae60943e4f183142036d77b94858085814dd428f131289aea7e42703fb0b02");

/// `policyRevision` slot (base + 3): `uint64`, right-aligned in its word.
pub const POLICY_REVISION_SLOT: B256 =
    b256!("0xa3ae60943e4f183142036d77b94858085814dd428f131289aea7e42703fb0b03");

/// `acceptedCount` slot (base + 4).
pub const ACCEPTED_COUNT_SLOT: B256 =
    b256!("0xa3ae60943e4f183142036d77b94858085814dd428f131289aea7e42703fb0b04");

/// The genesis policy revision. Revision 0 means uninitialized, so a
/// registry seeded from a compiled policy always starts at 1.
pub const GENESIS_POLICY_REVISION: u64 = 1;

/// `Status.Accepted` as a stored word.
const STATUS_ACCEPTED: B256 =
    b256!("0x0000000000000000000000000000000000000000000000000000000000000001");

/// Storage slot of `statuses[admissionId]`:
/// `keccak256(abi.encode(admissionId, REGISTRY_STORAGE_LOCATION))`.
pub fn admission_status_slot(admission_id: B256) -> B256 {
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(admission_id.as_slice());
    preimage[32..].copy_from_slice(REGISTRY_STORAGE_LOCATION.as_slice());
    keccak256(preimage)
}

/// The complete registry genesis storage for a compiled policy: every
/// compiled admission ID `Accepted`, bootstrap and active policy hashes both
/// set to the document hash, revision [`GENESIS_POLICY_REVISION`], and
/// `acceptedCount` equal to the unique-ID count. Deploy validation requires
/// the registry account to hold exactly this map and nothing else.
pub fn registry_genesis_storage(policy: &CompiledPolicy) -> BTreeMap<B256, B256> {
    let mut storage = BTreeMap::new();
    storage.insert(BOOTSTRAP_POLICY_HASH_SLOT, policy.policy_hash);
    storage.insert(ACTIVE_POLICY_HASH_SLOT, policy.policy_hash);
    storage.insert(
        POLICY_REVISION_SLOT,
        B256::from(U256::from(GENESIS_POLICY_REVISION)),
    );
    storage.insert(
        ACCEPTED_COUNT_SLOT,
        B256::from(U256::from(policy.admission_ids.len())),
    );
    for admission_id in &policy.admission_ids {
        storage.insert(admission_status_slot(*admission_id), STATUS_ACCEPTED);
    }
    storage
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recompute the EIP-7201 base from its defining expression, pinning the
    /// hardcoded constant to the namespace string (the Solidity twin is
    /// `test_StorageLocationMatchesERC7201Derivation`).
    #[test]
    fn storage_location_matches_erc7201_derivation() {
        let namespace_hash =
            U256::from_be_bytes(keccak256("seismic.storage.MeasurementRegistry".as_bytes()).0);
        let derived = keccak256(B256::from(namespace_hash - U256::from(1)));
        let mut masked = derived.0;
        masked[31] = 0;
        assert_eq!(B256::from(masked), REGISTRY_STORAGE_LOCATION);
    }

    #[test]
    fn field_slots_are_base_plus_offsets() {
        let base = U256::from_be_bytes(REGISTRY_STORAGE_LOCATION.0);
        for (offset, slot) in [
            (1u64, BOOTSTRAP_POLICY_HASH_SLOT),
            (2, ACTIVE_POLICY_HASH_SLOT),
            (3, POLICY_REVISION_SLOT),
            (4, ACCEPTED_COUNT_SLOT),
        ] {
            assert_eq!(B256::from(base + U256::from(offset)), slot);
        }
    }

    /// Golden value shared with `MeasurementRegistry.t.sol`
    /// (`INITIAL_ADMISSION_STATUS_SLOT`): the status slot of admission ID
    /// `bytes32(uint256(1))`.
    #[test]
    fn status_slot_golden_matches_solidity() {
        assert_eq!(
            admission_status_slot(B256::from(U256::from(1))),
            b256!("0x375f13b0f395f58180c4440e3093a15026ebe690dc75ff0edddf4387bd26fae6")
        );
    }
}
