use alloy_sol_types::SolCall;
use seismic_measurement_registry_client::MeasurementRegistry::isAcceptedCall;
use serde_json::Value;
use std::{env, fs, path::PathBuf};

const CANONICAL_ARTIFACT_ENV: &str = "MEASUREMENT_REGISTRY_ARTIFACT";

#[test]
fn runtime_read_selector_is_pinned() {
    assert_eq!(isAcceptedCall::SIGNATURE, "isAccepted(bytes32)");
    assert_eq!(isAcceptedCall::SELECTOR, [0xa7, 0x8f, 0x84, 0xcf]);
}

/// CI checks out `SeismicSystems/seismic` and points this test at its committed
/// canonical artifact. It is ignored in an ordinary local run because the
/// artifact intentionally remains in its owning repository.
#[test]
#[ignore = "CI supplies the canonical seismic/contracts artifact"]
fn runtime_read_interface_matches_canonical_artifact() {
    let path = PathBuf::from(env::var_os(CANONICAL_ARTIFACT_ENV).unwrap_or_else(|| {
        panic!("{CANONICAL_ARTIFACT_ENV} must point to MeasurementRegistry.json")
    }));
    let artifact: Value = serde_json::from_slice(
        &fs::read(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));

    let selector = isAcceptedCall::SELECTOR
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        artifact["methodIdentifiers"][isAcceptedCall::SIGNATURE],
        selector,
        "Rust call selector drifted from {}",
        path.display()
    );

    let canonical_function = artifact["abi"]
        .as_array()
        .expect("artifact ABI must be an array")
        .iter()
        .find(|item| item["type"] == "function" && item["name"] == "isAccepted")
        .expect("canonical artifact must expose isAccepted");
    assert_eq!(canonical_function["stateMutability"], "view");
    assert_eq!(canonical_function["inputs"][0]["type"], "bytes32");
    assert_eq!(canonical_function["outputs"][0]["type"], "bool");
    assert_eq!(
        canonical_function["inputs"]
            .as_array()
            .expect("function inputs must be an array")
            .len(),
        1
    );
    assert_eq!(
        canonical_function["outputs"]
            .as_array()
            .expect("function outputs must be an array")
            .len(),
        1
    );
}
