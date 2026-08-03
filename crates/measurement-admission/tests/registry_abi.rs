//! Selector parity between the enclave Rust registry interface and the
//! canonical Solidity artifact
//! (https://github.com/SeismicSystems/seismic/blob/main/contracts/artifacts/MeasurementRegistry.json).
//!
//! The artifact stays owned by the seismic repo: CI checks it out and points
//! `MEASUREMENT_REGISTRY_ARTIFACT` at it — the same env var
//! `seismic-measurement-registry-client`'s `abi_parity` test reads — so no
//! local ABI copy exists to go stale. Fetching is what makes these checks
//! meaningful: a committed copy could only show that this crate agrees with
//! the artifact it last saw, never that it agrees with the canonical one.
//!
//! With `reth_registry.rs` tying the genesis template's registry code to
//! [`REGISTRY_RUNTIME_CODE_HASH`], this closes the chain `genesis template
//! code <-> REGISTRY_RUNTIME_CODE_HASH <-> canonical artifact`: the ABI checked
//! here belongs to the exact runtime the chain installs, and an upstream
//! contract rebuild surfaces as a failure rather than a silent re-pin.

mod common;

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::PathBuf,
};

use alloy::primitives::keccak256;
use common::IMeasurementRegistry::IMeasurementRegistryCalls;
use seismic_measurement_admission::genesis::REGISTRY_RUNTIME_CODE_HASH;

const CANONICAL_ARTIFACT_ENV: &str = "MEASUREMENT_REGISTRY_ARTIFACT";

/// The protocol signatures [`common::IMeasurementRegistry`] is expected to
/// declare, pinned so that editing the interface fails locally instead of only
/// once CI supplies the canonical artifact.
const PINNED_SIGNATURES: [&str; 8] = [
    "AUTHORITY()",
    "acceptedCount()",
    "activePolicyHash()",
    "applyPolicyUpdate(bytes32[],bytes32[],bytes32)",
    "bootstrapPolicyHash()",
    "isAccepted(bytes32)",
    "policyRevision()",
    "statusOf(bytes32)",
];

fn selector_of(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes())[..4]
        .try_into()
        .expect("4-byte selector")
}

fn canonical_artifact() -> serde_json::Value {
    let path = PathBuf::from(env::var_os(CANONICAL_ARTIFACT_ENV).unwrap_or_else(|| {
        panic!("{CANONICAL_ARTIFACT_ENV} must point to MeasurementRegistry.json")
    }));
    let bytes = fs::read(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

#[test]
fn interface_selectors_are_pinned() {
    let pinned: BTreeSet<[u8; 4]> = PINNED_SIGNATURES.iter().copied().map(selector_of).collect();
    let declared: BTreeSet<[u8; 4]> = IMeasurementRegistryCalls::SELECTORS
        .iter()
        .copied()
        .collect();
    assert_eq!(
        pinned, declared,
        "IMeasurementRegistry no longer declares exactly the pinned protocol signatures"
    );
}

/// CI checks out `SeismicSystems/seismic` and points this test at its committed
/// canonical artifact. It is ignored in an ordinary local run because the
/// artifact intentionally remains in its owning repository.
#[test]
#[ignore = "CI supplies the canonical seismic/contracts artifact"]
fn runtime_code_pin_matches_canonical_artifact() {
    let code_hex = canonical_artifact()["deployedBytecode"]["object"]
        .as_str()
        .expect("deployedBytecode.object")
        .to_owned();
    let code = hex::decode(code_hex.trim_start_matches("0x")).expect("runtime code hex");
    assert_eq!(
        keccak256(&code),
        REGISTRY_RUNTIME_CODE_HASH,
        "REGISTRY_RUNTIME_CODE_HASH drifted from the canonical registry build; \
         re-pin it alongside the compiled fixture and the genesis template"
    );
}

#[test]
#[ignore = "CI supplies the canonical seismic/contracts artifact"]
fn rust_interface_selectors_match_canonical_abi() {
    let identifiers: BTreeMap<String, String> =
        serde_json::from_value(canonical_artifact()["methodIdentifiers"].clone())
            .expect("methodIdentifiers");
    let mut artifact_selectors: BTreeMap<[u8; 4], String> = BTreeMap::new();
    for (signature, selector) in identifiers {
        // Forge's methodIdentifiers are derived from the signature; recompute
        // rather than trust the artifact's own consistency.
        let selector: [u8; 4] = hex::decode(&selector)
            .expect("selector hex")
            .try_into()
            .expect("4-byte selector");
        assert_eq!(
            selector_of(&signature),
            selector,
            "artifact selector for `{signature}` is not the keccak of its signature"
        );
        artifact_selectors.insert(selector, signature);
    }

    for (selector, signature) in &artifact_selectors {
        assert!(
            IMeasurementRegistryCalls::SELECTORS.contains(selector),
            "canonical ABI function `{signature}` is missing from the Rust \
             IMeasurementRegistry interface"
        );
    }
    let unknown: Vec<String> = IMeasurementRegistryCalls::SELECTORS
        .iter()
        .filter(|selector| !artifact_selectors.contains_key(*selector))
        .map(hex::encode)
        .collect();
    assert!(
        unknown.is_empty(),
        "Rust IMeasurementRegistry interface declares selectors absent from the \
         canonical ABI: {unknown:?}"
    );
}
