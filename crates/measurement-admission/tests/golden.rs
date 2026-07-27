//! The committed fixture pair pins the whole pipeline — parsing,
//! normalization, admission-ID derivation, policy hashing, and
//! genesis-storage derivation — across releases; other stacks (e.g. deploy
//! tooling tests) can assert the same files so every implementation pins
//! identical bytes. Any intentional change to the derivation must regenerate
//! the compiled fixture deliberately.

use seismic_measurement_admission::{CompileReport, compile_policy};

const POLICY: &[u8] = include_bytes!("../fixtures/measurement-policy-v1.json");
const COMPILED: &str = include_str!("../fixtures/measurement-policy-v1.compiled.json");

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
