//! Parity tests pinning the compiler's accepted semantics to attested-tls's
//! `MeasurementPolicy::check_measurement` — the matcher the attestation
//! stack applies during evidence verification. Every guest the compiler
//! admits must be a guest attested-tls admits under the same document, and
//! record correlation must hold on both sides, so the two implementations
//! of the admission predicate cannot drift apart.
//! (The compiler is deliberately the stricter parser: documents it rejects
//! may still parse under attested-tls's permissive loader.)

use attestation::measurements::{DcapMeasurements, MeasurementPolicy, MultiMeasurements};
use attestation::{AttestationError, AttestationType, PlatformMetadata};
use seismic_measurement_admission::{
    AzureTdxV1Measurements, GcpTdxV1Measurements, SchemaTuple, compile_policy,
};
use std::collections::HashMap;

const POLICY: &[u8] = include_bytes!("../fixtures/golden/measurement-policy-v1.json");
const MIXED_POLICY: &[u8] = include_bytes!("../fixtures/golden/measurement-policy-v1.mixed.json");

/// Run a compiled tuple through attested-tls as its platform's evidence.
fn check(policy: &MeasurementPolicy, tuple: &SchemaTuple) -> Result<(), AttestationError> {
    let (evidence, platform) = match tuple {
        SchemaTuple::AzureTdxV1(tuple) => (as_azure_evidence(tuple), None),
        SchemaTuple::GcpTdxV1(tuple) => (as_gcp_evidence(tuple), Some(gcp_platform())),
    };
    policy
        .check_measurement(&evidence, platform.as_ref())
        .map(drop)
}

/// Present a tuple the way verified Azure evidence would surface it.
fn as_azure_evidence(tuple: &AzureTdxV1Measurements) -> MultiMeasurements {
    let mut pcrs: HashMap<u32, [u8; 32]> = HashMap::new();
    pcrs.insert(4, tuple.pcr4.0);
    pcrs.insert(9, tuple.pcr9.0);
    pcrs.insert(11, tuple.pcr11.0);
    MultiMeasurements::Azure(pcrs)
}

/// Present a tuple as verified GCP evidence, with filler in the registers the schema leaves unbound.
fn as_gcp_evidence(tuple: &GcpTdxV1Measurements) -> MultiMeasurements {
    let unbound = [0; 48];
    MultiMeasurements::Dcap(DcapMeasurements::new(
        unbound,
        unbound,
        tuple.rtmr1,
        tuple.rtmr2,
        unbound,
    ))
}

/// attested-tls types DCAP evidence as `dcap-tdx` unless the platform
/// metadata names `gcp-tdx`.
fn gcp_platform() -> PlatformMetadata {
    PlatformMetadata {
        attestation_type: AttestationType::GcpTdx.try_into().unwrap(),
        ram_bytes: 0,
        num_disks: 0,
        acpi: None,
        smbios_handoff: None,
        dm_verity_boot: false,
    }
}

#[test]
fn every_compiled_tuple_is_accepted_by_attested_tls() {
    for doc in [POLICY, MIXED_POLICY] {
        let compiled = compile_policy(doc).unwrap();
        let policy = MeasurementPolicy::from_json_bytes(doc.to_vec()).unwrap();
        for record in &compiled.records {
            check(&policy, &record.tuple).unwrap_or_else(|e| {
                panic!(
                    "attested-tls rejected the compiled tuple of {:?}: {e:?}",
                    record.measurement_id
                )
            });
        }
    }
}

#[test]
fn cross_record_flattening_is_rejected_by_both() {
    let compiled = compile_policy(POLICY).unwrap();
    let policy = MeasurementPolicy::from_json_bytes(POLICY.to_vec()).unwrap();

    // Record 0's PCR4 with record 1's PCR9/PCR11 is a synthetic image
    // neither side may admit.
    let flattened = AzureTdxV1Measurements {
        pcr4: azure_tuple(&compiled.records[0].tuple).pcr4,
        pcr9: azure_tuple(&compiled.records[1].tuple).pcr9,
        pcr11: azure_tuple(&compiled.records[1].tuple).pcr11,
    };
    assert!(!compiled.admission_ids.contains(&flattened.admission_id()));
    assert!(check(&policy, &SchemaTuple::AzureTdxV1(flattened)).is_err());
}

#[test]
fn gcp_cross_record_flattening_is_rejected_by_both() {
    let doc = two_gcp_records();
    let compiled = compile_policy(doc.as_bytes()).unwrap();
    let policy = MeasurementPolicy::from_json_bytes(doc.into_bytes()).unwrap();
    for record in &compiled.records {
        check(&policy, &record.tuple).unwrap();
    }

    let flattened = GcpTdxV1Measurements {
        rtmr1: gcp_tuple(&compiled.records[0].tuple).rtmr1,
        rtmr2: gcp_tuple(&compiled.records[1].tuple).rtmr2,
    };
    assert!(!compiled.admission_ids.contains(&flattened.admission_id()));
    assert!(check(&policy, &SchemaTuple::GcpTdxV1(flattened)).is_err());
}

#[test]
fn evidence_of_the_other_platform_is_rejected_by_both() {
    let mixed = compile_policy(MIXED_POLICY).unwrap();
    let azure_only = compile_policy(POLICY).unwrap();
    let policy = MeasurementPolicy::from_json_bytes(POLICY.to_vec()).unwrap();

    let gcp = mixed
        .records
        .iter()
        .find(|record| matches!(record.tuple, SchemaTuple::GcpTdxV1(_)))
        .unwrap();
    assert!(!azure_only.admission_ids.contains(&gcp.tuple.admission_id()));
    assert!(check(&policy, &gcp.tuple).is_err());
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
    assert!(check(&policy, &compiled.records[0].tuple).is_ok());
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

/// Two gcp-tdx records that share no register value.
fn two_gcp_records() -> String {
    let rtmr1_a = "762d5dc2b8dcd950b77ba759e2321a865a7a1fcdeb1f5d879f3e31e974c9697fa4171d92e08c2243a91af3027ad08cb0";
    let rtmr2_a = "85bc309a887ad0277ea50d47aacb850d080c498e2e713eeab0d035085acbd6d47ac06f276ae4284c828dc199e6845031";
    let rtmr1_b = "a1".repeat(48);
    let rtmr2_b = "b2".repeat(48);
    format!(
        r#"[{{"attestation_type":"gcp-tdx","measurement_id":"a","measurements":{{
            "rtmr1":{{"expected_any":["{rtmr1_a}"]}},
            "rtmr2":{{"expected_any":["{rtmr2_a}"]}}}}}},
          {{"attestation_type":"gcp-tdx","measurement_id":"b","measurements":{{
            "rtmr1":{{"expected_any":["{rtmr1_b}"]}},
            "rtmr2":{{"expected_any":["{rtmr2_b}"]}}}}}}]"#
    )
}

fn azure_tuple(tuple: &SchemaTuple) -> &AzureTdxV1Measurements {
    match tuple {
        SchemaTuple::AzureTdxV1(tuple) => tuple,
        other => panic!("expected an azure-tdx record, got {other:?}"),
    }
}

fn gcp_tuple(tuple: &SchemaTuple) -> &GcpTdxV1Measurements {
    match tuple {
        SchemaTuple::GcpTdxV1(tuple) => tuple,
        other => panic!("expected a gcp-tdx record, got {other:?}"),
    }
}
