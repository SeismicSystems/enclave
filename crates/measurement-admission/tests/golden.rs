//! The committed golden fixtures pin the whole pipeline — parsing,
//! normalization, admission-ID derivation, policy hashing, and
//! genesis-storage derivation — across releases; other stacks (e.g. deploy
//! tooling tests) can assert the same files so every implementation pins
//! identical bytes. Any intentional change to the derivation must regenerate
//! the compiled reports deliberately.

use seismic_measurement_admission::{CompileReport, compile_policy, promote_measurements};

const POLICY: &[u8] = include_bytes!("../fixtures/golden/measurement-policy-v1.json");
const COMPILED: &str = include_str!("../fixtures/golden/measurement-policy-v1.compiled.json");
const RAW_MEASUREMENTS: &[u8] =
    include_bytes!("../fixtures/golden/make-measure-output.image-a.json");
const IMAGE_A_POLICY: &[u8] =
    include_bytes!("../fixtures/golden/measurement-policy-v1.image-a.json");
const IMAGE_B_POLICY: &[u8] =
    include_bytes!("../fixtures/golden/measurement-policy-v1.image-b.json");
const IMAGE_B_COMPILED: &str =
    include_str!("../fixtures/golden/measurement-policy-v1.image-b.compiled.json");

#[test]
fn fixture_compiles_to_committed_report() {
    let compiled = compile_policy(POLICY).expect("fixture compiles");
    assert_eq!(CompileReport::new(&compiled).to_json(), COMPILED);
}

#[test]
fn image_b_fixture_compiles_to_committed_report() {
    let compiled = compile_policy(IMAGE_B_POLICY).expect("fixture compiles");
    assert_eq!(CompileReport::new(&compiled).to_json(), IMAGE_B_COMPILED);
}

/// The three golden documents are the revision sequence the policy lifecycle
/// walks: image A alone, both images, image B alone. Their accepted sets are
/// exactly the subsets that makes each step one status delta.
#[test]
fn golden_documents_are_the_revision_sequence() {
    let image_a = compile_policy(IMAGE_A_POLICY).unwrap().admission_ids;
    let both = compile_policy(POLICY).unwrap().admission_ids;
    let image_b = compile_policy(IMAGE_B_POLICY).unwrap().admission_ids;

    assert_eq!(image_a.len(), 1);
    assert_eq!(image_b.len(), 1);
    assert_eq!(both, {
        let mut union = vec![image_a[0], image_b[0]];
        union.sort();
        union
    });
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
    assert_eq!(promoted, IMAGE_A_POLICY);
}

#[test]
fn promoted_fixture_passes_through_and_compiles() {
    // The committed promoted document is itself valid promoter input (the
    // manifest commits to its exact bytes) and admits the identity the raw
    // measurements state.
    let passed = promote_measurements(IMAGE_A_POLICY, None, None).unwrap();
    assert_eq!(passed, IMAGE_A_POLICY);
    let compiled = compile_policy(IMAGE_A_POLICY).unwrap();
    assert_eq!(compiled.records.len(), 1);
    assert_eq!(
        compiled.records[0].measurement_id,
        "seismic-dev_2026-07-02.5c3b5e.vhd"
    );
}
