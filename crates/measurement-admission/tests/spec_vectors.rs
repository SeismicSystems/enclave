//! Every hex value in `SPEC.md` is recomputed here from the golden fixtures
//! and the frozen constants, so the normative prose cannot drift from the
//! implementation it specifies. The check runs both ways: a value in the
//! document that nothing derives fails, and a derived value the document
//! stopped quoting fails too.

use seismic_measurement_admission::{
    AdmissionId, AzureTdxV1Measurements, CompiledPolicy, azure_tdx_v1_schema_id, compile_policy,
    genesis::{
        ACCEPTED_COUNT_SLOT, ACTIVE_POLICY_HASH_SLOT, BOOTSTRAP_POLICY_HASH_SLOT,
        POLICY_REVISION_SLOT, REGISTRY_RUNTIME_CODE_HASH, REGISTRY_STORAGE_LOCATION,
        admission_status_slot,
    },
};

const SPEC: &str = include_str!("../SPEC.md");

const POLICY_A: &[u8] = include_bytes!("../fixtures/golden/measurement-policy-v1.image-a.json");
const POLICY_AB: &[u8] = include_bytes!("../fixtures/golden/measurement-policy-v1.json");
const POLICY_B: &[u8] = include_bytes!("../fixtures/golden/measurement-policy-v1.image-b.json");

/// Lowercase, unprefixed hex of one 32-byte value.
fn hex32(word: impl Into<alloy_primitives::B256>) -> String {
    hex::encode(word.into())
}

fn id_hex(id: AdmissionId) -> String {
    hex32(*id.as_b256())
}

/// Every 32-byte value the specification is allowed to quote: the schema
/// word, the three documents' hashes/IDs/tuples/status slots, the frozen
/// layout constants, and the flattened cross-product IDs the document shows
/// as *excluded*.
fn derived_values() -> Vec<String> {
    let mut values = vec![
        hex32(azure_tdx_v1_schema_id()),
        hex32(REGISTRY_STORAGE_LOCATION),
        hex32(BOOTSTRAP_POLICY_HASH_SLOT),
        hex32(ACTIVE_POLICY_HASH_SLOT),
        hex32(POLICY_REVISION_SLOT),
        hex32(ACCEPTED_COUNT_SLOT),
        hex32(REGISTRY_RUNTIME_CODE_HASH),
    ];

    for document in [POLICY_A, POLICY_AB, POLICY_B] {
        let compiled = compile_policy(document).expect("fixture compiles");
        values.push(hex32(compiled.policy_hash));
        for id in &compiled.admission_ids {
            values.push(id_hex(*id));
            values.push(hex32(admission_status_slot(*id)));
        }
        for record in &compiled.records {
            values.push(hex32(record.tuple.pcr4));
            values.push(hex32(record.tuple.pcr9));
            values.push(hex32(record.tuple.pcr11));
        }
    }

    for tuple in flattened_tuples() {
        values.push(id_hex(tuple.admission_id()));
    }
    values
}

/// The two mixed tuples the specification names: image A's boot binary with
/// image B's command line and UKI, and the reverse. A flattening compiler
/// would admit both; this one must not.
fn flattened_tuples() -> [AzureTdxV1Measurements; 2] {
    let a = tuple_of(POLICY_A);
    let b = tuple_of(POLICY_B);
    [
        AzureTdxV1Measurements {
            pcr4: a.pcr4,
            pcr9: b.pcr9,
            pcr11: b.pcr11,
        },
        AzureTdxV1Measurements {
            pcr4: b.pcr4,
            pcr9: a.pcr9,
            pcr11: a.pcr11,
        },
    ]
}

fn tuple_of(single_record_document: &[u8]) -> AzureTdxV1Measurements {
    let compiled = compile_single(single_record_document);
    compiled.records[0].tuple
}

fn compile_single(document: &[u8]) -> CompiledPolicy {
    let compiled = compile_policy(document).expect("fixture compiles");
    assert_eq!(compiled.records.len(), 1, "expected a one-record document");
    compiled
}

/// How the document quotes one 32-byte value.
#[derive(Clone, Copy, Debug)]
enum Quoted {
    /// A full 64-character run, checked whole.
    Whole,
    /// `0x98ba9f24...`, checked as a prefix.
    Head,
    /// `0x...0b01`, checked as a suffix. The genesis-storage table names the
    /// namespace base once and abbreviates each field slot to its offset.
    Tail,
}

/// Hex runs in the document, paired with how they must be checked. Anything
/// else — addresses, `0xff`, digits inside artifact names — carries no vector
/// and is skipped.
fn quoted_hex(text: &str) -> Vec<(String, Quoted)> {
    let bytes = text.as_bytes();
    let mut quoted = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        if !bytes[start].is_ascii_hexdigit() {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
            end += 1;
        }
        let run = text[start..end].to_ascii_lowercase();
        let form = if run.len() == 64 {
            Some(Quoted::Whole)
        } else if run.len() >= 4 && text[end..].starts_with("...") {
            Some(Quoted::Head)
        } else if run.len() >= 4 && text[..start].ends_with("...") {
            Some(Quoted::Tail)
        } else {
            None
        };
        if let Some(form) = form {
            quoted.push((run, form));
        }
        start = end;
    }
    quoted
}

#[test]
fn every_hex_value_in_the_spec_is_derived() {
    let derived = derived_values();
    let quoted = quoted_hex(SPEC);
    assert!(
        quoted.len() > 30,
        "expected the spec to quote its vectors; found {} hex runs",
        quoted.len()
    );

    for (value, form) in quoted {
        let matched = derived.iter().any(|candidate| match form {
            Quoted::Whole => *candidate == value,
            Quoted::Head => candidate.starts_with(&value),
            Quoted::Tail => candidate.ends_with(&value),
        });
        assert!(
            matched,
            "SPEC.md quotes {}, which nothing in the fixtures or frozen constants \
             derives; regenerate the spec's worked examples",
            match form {
                Quoted::Whole => format!("0x{value}"),
                Quoted::Head => format!("0x{value}..."),
                Quoted::Tail => format!("0x...{value}"),
            }
        );
    }
}

#[test]
fn spec_quotes_every_document_hash_and_admission_id() {
    let spec = SPEC.to_ascii_lowercase();
    for document in [POLICY_A, POLICY_AB, POLICY_B] {
        let compiled = compile_policy(document).unwrap();
        let hash = hex32(compiled.policy_hash);
        assert!(
            spec.contains(&hash),
            "SPEC.md does not quote policy hash 0x{hash}"
        );
        for id in &compiled.admission_ids {
            let id = id_hex(*id);
            assert!(
                spec.contains(&id),
                "SPEC.md does not quote admission ID 0x{id}"
            );
        }
    }
}

#[test]
fn spec_quotes_the_layout_constants_and_excluded_ids() {
    let spec = SPEC.to_ascii_lowercase();
    for value in [
        hex32(azure_tdx_v1_schema_id()),
        hex32(REGISTRY_STORAGE_LOCATION),
        hex32(REGISTRY_RUNTIME_CODE_HASH),
    ] {
        assert!(spec.contains(&value), "SPEC.md does not quote 0x{value}");
    }

    // The status slots of both fixture identities, as the genesis-storage
    // table lists them.
    for document in [POLICY_A, POLICY_B] {
        let id = compile_single(document).records[0].admission_id();
        let slot = hex32(admission_status_slot(id));
        assert!(
            spec.contains(&slot),
            "SPEC.md does not quote status slot 0x{slot}"
        );
    }

    // The flattened tuples must be shown, and must be absent from the
    // two-record document's accepted set.
    let accepted = compile_policy(POLICY_AB).unwrap().admission_ids;
    for tuple in flattened_tuples() {
        let id = tuple.admission_id();
        assert!(
            spec.contains(&id_hex(id)),
            "SPEC.md does not quote excluded ID 0x{}",
            id_hex(id)
        );
        assert!(
            !accepted.contains(&id),
            "flattened tuple {id} is in the accepted set"
        );
    }
}
