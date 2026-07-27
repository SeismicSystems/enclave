//! Parity tests pinning the compiler's accepted semantics to attested-tls's
//! `MeasurementPolicy::check_measurement` — the matcher the attestation
//! stack applies during evidence verification. Every guest the compiler
//! admits must be a guest attested-tls admits under the same document, and
//! record correlation must hold on both sides, so the two implementations
//! of the admission predicate cannot drift apart.
//! (The compiler is deliberately the stricter parser: documents it rejects
//! may still parse under attested-tls's permissive loader.)

use attestation::measurements::{MeasurementPolicy, MultiMeasurements};
use seismic_measurement_admission::{AzureTdxV1Measurements, compile_policy};
use std::collections::HashMap;

const POLICY: &[u8] = include_bytes!("../fixtures/measurement-policy-v1.json");

/// Present a tuple the way verified Azure evidence would surface it.
fn as_azure_evidence(tuple: &AzureTdxV1Measurements) -> MultiMeasurements {
    let mut pcrs: HashMap<u32, [u8; 32]> = HashMap::new();
    pcrs.insert(4, tuple.pcr4.0);
    pcrs.insert(9, tuple.pcr9.0);
    pcrs.insert(11, tuple.pcr11.0);
    MultiMeasurements::Azure(pcrs)
}

#[test]
fn every_compiled_tuple_is_accepted_by_attested_tls() {
    let compiled = compile_policy(POLICY).unwrap();
    let policy = MeasurementPolicy::from_json_bytes(POLICY.to_vec()).unwrap();
    for record in &compiled.records {
        policy
            .check_measurement(&as_azure_evidence(&record.tuple))
            .unwrap_or_else(|e| {
                panic!(
                    "attested-tls rejected the compiled tuple of {:?}: {e:?}",
                    record.measurement_id
                )
            });
    }
}

#[test]
fn cross_record_flattening_is_rejected_by_both() {
    let compiled = compile_policy(POLICY).unwrap();
    let policy = MeasurementPolicy::from_json_bytes(POLICY.to_vec()).unwrap();

    // Record 0's PCR4 with record 1's PCR9/PCR11 is a synthetic image
    // neither side may admit.
    let flattened = AzureTdxV1Measurements {
        pcr4: compiled.records[0].tuple.pcr4,
        pcr9: compiled.records[1].tuple.pcr9,
        pcr11: compiled.records[1].tuple.pcr11,
    };
    assert!(!compiled.admission_ids.contains(&flattened.admission_id()));
    assert!(
        policy
            .check_measurement(&as_azure_evidence(&flattened))
            .is_err()
    );
}

#[test]
fn deprecated_expected_form_matches_on_both_sides() {
    let value = "d57063c0669599b885c43a0683436a3463ad49513ddb3996e6fc96040508fd8e";
    let doc = format!(
        r#"[{{"attestation_type":"azure-tdx","measurement_id":"x","measurements":{{
            "4":{{"expected":"{value}"}},
            "9":{{"expected":"{value}"}},
            "11":{{"expected":"{value}"}}}}}}]"#
    );
    let compiled = compile_policy(doc.as_bytes()).unwrap();
    let policy = MeasurementPolicy::from_json_bytes(doc.into_bytes()).unwrap();
    assert_eq!(compiled.admission_ids.len(), 1);
    let tuple = &compiled.records[0].tuple;
    assert!(policy.check_measurement(&as_azure_evidence(tuple)).is_ok());
}

#[test]
fn multi_value_records_are_rejected_here_but_parse_upstream() {
    // attested-tls's per-register `expected_any` OR admits the Cartesian
    // product of a record's value lists. Seismic policies bind one value per
    // register — one record, one guest identity — so the compiler rejects
    // the multi-value form that upstream happily matches; a set of
    // identities is authored as one record per identity.
    let value = "d57063c0669599b885c43a0683436a3463ad49513ddb3996e6fc96040508fd8e";
    let other = "3f761a6383e09d62ac10ecfea95c27e30de69176337243e7e594714d27f6ac45";
    let doc = format!(
        r#"[{{"attestation_type":"azure-tdx","measurement_id":"x","measurements":{{
            "pcr4":{{"expected_any":["{value}","{other}"]}},
            "pcr9":{{"expected_any":["{value}"]}},
            "pcr11":{{"expected_any":["{value}"]}}}}}}]"#
    );
    assert!(MeasurementPolicy::from_json_bytes(doc.clone().into_bytes()).is_ok());
    assert!(compile_policy(doc.as_bytes()).is_err());
}
