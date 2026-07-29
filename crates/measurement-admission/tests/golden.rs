//! The committed fixture pair pins the whole pipeline — parsing,
//! normalization, admission-ID derivation, policy hashing, and
//! genesis-storage derivation — across releases; other stacks (e.g. deploy
//! tooling tests) can assert the same files so every implementation pins
//! identical bytes. Any intentional change to the derivation must regenerate
//! the compiled fixture deliberately.

use seismic_measurement_admission::{CompileReport, compile_policy, promote_measurements};

const POLICY: &[u8] = include_bytes!("../fixtures/golden/measurement-policy-v1.json");
const COMPILED: &str = include_str!("../fixtures/golden/measurement-policy-v1.compiled.json");
const RAW_MEASUREMENTS: &[u8] = include_bytes!("../fixtures/golden/make-measure-output.json");
const PROMOTED: &[u8] = include_bytes!("../fixtures/golden/make-measure-output.promoted.json");

#[test]
fn fixture_compiles_to_committed_report() {
    let compiled = compile_policy(POLICY).expect("fixture compiles");
    assert_eq!(CompileReport::new(&compiled).to_json(), COMPILED);
}

#[test]
fn fixture_compiles_to_one_id_per_record() {
    let compiled = compile_policy(POLICY).unwrap();
    assert_eq!(compiled.records.len(), 2);
    assert_eq!(compiled.admission_ids.len(), 2);
}

#[test]
fn fixture_promotes_to_committed_policy_document() {
    let promoted = promote_measurements(RAW_MEASUREMENTS, None, None).expect("fixture promotes");
    assert_eq!(promoted, PROMOTED);
}

#[test]
fn promoted_fixture_passes_through_and_compiles() {
    // The committed promoted document is itself valid promoter input (the
    // manifest commits to its exact bytes) and admits the identity the raw
    // measurements state.
    let passed = promote_measurements(PROMOTED, None, None).unwrap();
    assert_eq!(passed, PROMOTED);
    let compiled = compile_policy(PROMOTED).unwrap();
    assert_eq!(compiled.records.len(), 1);
    assert_eq!(
        compiled.records[0].measurement_id,
        "seismic-dev_2026-07-02.5c3b5e.vhd"
    );
}
