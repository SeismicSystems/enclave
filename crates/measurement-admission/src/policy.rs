//! Compiler from a measurement-policy document to the admission IDs it
//! admits.
//!
//! The document format is the Flashbots-compatible record list attested-tls
//! parses (`MeasurementPolicy::from_json_bytes`): records are ORed and
//! registers within one record are ANDed (a deprecated scalar `expected`
//! means a one-element `expected_any`). Seismic policies restrict the
//! format's per-register OR: an `expected_any` list must contain exactly one
//! value, so one record is one concrete `(pcr4, pcr9, pcr11)` guest identity
//! and compiles to exactly one admission ID. Any accepted set is still
//! expressible — one record per identity — and the document stays literal:
//! the identities governance reviews are the records the document lists.
//!
//! A document that seeds chain state must be exact, so this compiler is
//! deliberately stricter than attested-tls's permissive matcher: every
//! record must carry exactly the schema registers, each spelled once, each
//! binding a single 32-byte value. Parity tests hold the accepted semantics
//! equal to `check_measurement` for every document this compiler accepts.

use crate::{
    AZURE_TDX_ATTESTATION_TYPE, AZURE_TDX_V1_PCRS, AZURE_TDX_V1_SCHEMA, AdmissionId,
    AzureTdxV1Measurements, GCP_TDX_ATTESTATION_TYPE, GCP_TDX_V1_SCHEMA, GcpTdxV1Measurements,
    azure_tdx_v1_schema_id, gcp_tdx_v1_schema_id,
};
use alloy_primitives::B256;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// The compiled form of one policy document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledPolicy {
    /// SHA-256 of the exact document bytes. This is the manifest's
    /// `bootstrap_policy_hash` and the registry's `bootstrapPolicyHash` /
    /// `activePolicyHash` at genesis.
    pub policy_hash: B256,
    /// Per-record identities, in document order.
    pub records: Vec<CompiledRecord>,
    /// Unique admission IDs across all records, ascending. The length is the
    /// registry's `acceptedCount` at genesis.
    pub admission_ids: Vec<AdmissionId>,
}

/// A record's measurement tuple under the schema its attestation type selects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaTuple {
    AzureTdxV1(AzureTdxV1Measurements),
    GcpTdxV1(GcpTdxV1Measurements),
}

impl SchemaTuple {
    pub fn admission_id(&self) -> AdmissionId {
        match self {
            Self::AzureTdxV1(tuple) => tuple.admission_id(),
            Self::GcpTdxV1(tuple) => tuple.admission_id(),
        }
    }

    pub fn schema(&self) -> &'static str {
        match self {
            Self::AzureTdxV1(_) => AZURE_TDX_V1_SCHEMA,
            Self::GcpTdxV1(_) => GCP_TDX_V1_SCHEMA,
        }
    }

    pub fn schema_id(&self) -> B256 {
        match self {
            Self::AzureTdxV1(_) => azure_tdx_v1_schema_id(),
            Self::GcpTdxV1(_) => gcp_tdx_v1_schema_id(),
        }
    }
}

/// One record's compiled form: the concrete guest identity it admits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledRecord {
    /// The record's human audit label; not part of guest identity.
    pub measurement_id: String,
    /// The record's measurement tuple.
    pub tuple: SchemaTuple,
}

impl CompiledRecord {
    /// Admission ID of this record's tuple.
    pub fn admission_id(&self) -> AdmissionId {
        self.tuple.admission_id()
    }
}

/// Why a policy document failed to compile.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy document is not a valid record list: {0}")]
    Json(#[from] serde_json::Error),
    #[error("policy document contains no records")]
    Empty,
    #[error(
        "{record}: unsupported attestation_type {attestation_type:?} \
         (supported: {AZURE_TDX_ATTESTATION_TYPE:?}, {GCP_TDX_ATTESTATION_TYPE:?})"
    )]
    UnsupportedAttestationType {
        record: String,
        attestation_type: String,
    },
    #[error(
        "{record}: attestation_type differs from the document's first record; a policy document pins one attestation type"
    )]
    MixedAttestationTypes { record: String },
    #[error(
        "{record}: register key {key:?} is not an admission register of this schema (expected \"rtmr1\")"
    )]
    UnexpectedGcpRegister { record: String, key: String },
    #[error("{record}: missing required register rtmr1")]
    MissingGcpRegister { record: String },
    #[error("{record}: {register} sets both expected and expected_any")]
    BothValueForms { record: String, register: String },
    #[error("{record}: {register} sets neither expected nor expected_any")]
    NoValueForm { record: String, register: String },
    #[error("{record}: {register} must bind exactly one accepted value, got {count}")]
    NotExactlyOneValue {
        record: String,
        register: String,
        count: usize,
    },
    #[error("{record}: {register} value {value:?} is not {len} bytes of bare hex")]
    BadValueLength {
        record: String,
        register: String,
        value: String,
        len: usize,
    },
    #[error("{record}: measurement_id duplicates an earlier record's")]
    DuplicateMeasurementId { record: String },
    #[error("{record}: register key {key:?} is not a PCR index (\"4\" or \"pcr4\", 0-23)")]
    BadRegisterKey { record: String, key: String },
    #[error("{record}: register key {key:?} duplicates pcr{index} after normalization")]
    DuplicateRegister {
        record: String,
        key: String,
        index: u32,
    },
    #[error("{record}: pcr{index} is not an admission register of this schema")]
    UnexpectedRegister { record: String, index: u32 },
    #[error("{record}: missing required register pcr{index}")]
    MissingRegister { record: String, index: u32 },
    #[error("{record}: pcr{index} sets both expected and expected_any")]
    BothExpectedForms { record: String, index: u32 },
    #[error("{record}: pcr{index} sets neither expected nor expected_any")]
    NoExpectedValue { record: String, index: u32 },
    #[error(
        "{record}: pcr{index} must bind exactly one accepted value, got {count} \
         (one record admits one guest identity; author one record per identity)"
    )]
    SingleValueRequired {
        record: String,
        index: u32,
        count: usize,
    },
    #[error("{record}: pcr{index} value {value:?} is not 32 bytes of bare hex")]
    BadValue {
        record: String,
        index: u32,
        value: String,
    },
}

/// A raw policy record. `deny_unknown_fields` rejects stray keys instead of
/// letting them ride along unreviewed, and a record without `measurements`
/// (attested-tls's accept-anything form) fails as a missing field: an
/// admission policy has no wildcard records.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecord {
    measurement_id: String,
    attestation_type: String,
    measurements: BTreeMap<String, RawEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawEntry {
    #[serde(default)]
    expected: Option<String>,
    #[serde(default)]
    expected_any: Option<Vec<String>>,
}

/// Compile a policy document's exact bytes into the admission IDs it admits.
pub fn compile_policy(bytes: &[u8]) -> Result<CompiledPolicy, PolicyError> {
    let raw_records: Vec<RawRecord> = serde_json::from_slice(bytes)?;
    if raw_records.is_empty() {
        return Err(PolicyError::Empty);
    }

    let mut seen_measurement_ids: HashSet<&str> = HashSet::new();
    let mut unique_ids: BTreeSet<AdmissionId> = BTreeSet::new();
    let mut records = Vec::with_capacity(raw_records.len());

    for (position, raw) in raw_records.iter().enumerate() {
        let record = format!("record {position} ({:?})", raw.measurement_id);

        if raw.attestation_type != AZURE_TDX_ATTESTATION_TYPE
            && raw.attestation_type != GCP_TDX_ATTESTATION_TYPE
        {
            return Err(PolicyError::UnsupportedAttestationType {
                record,
                attestation_type: raw.attestation_type.clone(),
            });
        }
        if raw.attestation_type != raw_records[0].attestation_type {
            return Err(PolicyError::MixedAttestationTypes { record });
        }
        if !seen_measurement_ids.insert(&raw.measurement_id) {
            return Err(PolicyError::DuplicateMeasurementId { record });
        }
        if raw.attestation_type == GCP_TDX_ATTESTATION_TYPE {
            let tuple = compile_gcp_record(&record, &raw.measurements)?;
            unique_ids.insert(tuple.admission_id());
            records.push(CompiledRecord {
                measurement_id: raw.measurement_id.clone(),
                tuple: SchemaTuple::GcpTdxV1(tuple),
            });
            continue;
        }

        // Normalize register keys, rejecting aliases that collapse to the
        // same index ("4" plus "pcr4") — a document carrying both is not
        // reviewable as written.
        let mut values: BTreeMap<u32, B256> = BTreeMap::new();
        for (key, entry) in &raw.measurements {
            let index = parse_pcr_key(key).ok_or_else(|| PolicyError::BadRegisterKey {
                record: record.clone(),
                key: key.clone(),
            })?;
            if values.contains_key(&index) {
                return Err(PolicyError::DuplicateRegister {
                    record,
                    key: key.clone(),
                    index,
                });
            }
            if !AZURE_TDX_V1_PCRS.contains(&index) {
                return Err(PolicyError::UnexpectedRegister { record, index });
            }
            values.insert(index, entry_value(&record, index, entry)?);
        }
        for index in AZURE_TDX_V1_PCRS {
            if !values.contains_key(&index) {
                return Err(PolicyError::MissingRegister { record, index });
            }
        }

        let tuple = AzureTdxV1Measurements {
            pcr4: values[&4],
            pcr9: values[&9],
            pcr11: values[&11],
        };
        unique_ids.insert(tuple.admission_id());
        records.push(CompiledRecord {
            measurement_id: raw.measurement_id.clone(),
            tuple: SchemaTuple::AzureTdxV1(tuple),
        });
    }

    Ok(CompiledPolicy {
        policy_hash: B256::from(<[u8; 32]>::from(Sha256::digest(bytes))),
        records,
        admission_ids: unique_ids.into_iter().collect(),
    })
}

/// Compile one `gcp-tdx` record: exactly the `rtmr1` register, one 48-byte value.
fn compile_gcp_record(
    record: &str,
    measurements: &BTreeMap<String, RawEntry>,
) -> Result<GcpTdxV1Measurements, PolicyError> {
    let mut rtmr1 = None;
    for (key, entry) in measurements {
        if !key.eq_ignore_ascii_case("rtmr1") {
            return Err(PolicyError::UnexpectedGcpRegister {
                record: record.to_owned(),
                key: key.clone(),
            });
        }
        if rtmr1.is_some() {
            return Err(PolicyError::UnexpectedGcpRegister {
                record: record.to_owned(),
                key: key.clone(),
            });
        }
        rtmr1 = Some(entry_value_bytes(record, "rtmr1", entry, 48)?);
    }
    let rtmr1 = rtmr1.ok_or_else(|| PolicyError::MissingGcpRegister {
        record: record.to_owned(),
    })?;
    Ok(GcpTdxV1Measurements {
        rtmr1: rtmr1.try_into().expect("length checked"),
    })
}

/// `expected` / `expected_any` binding exactly one bare-hex value of `len` bytes.
pub(crate) fn entry_value_bytes(
    record: &str,
    register: &str,
    entry: &RawEntry,
    len: usize,
) -> Result<Vec<u8>, PolicyError> {
    let value = match (&entry.expected, &entry.expected_any) {
        (Some(_), Some(_)) => {
            return Err(PolicyError::BothValueForms {
                record: record.to_owned(),
                register: register.to_owned(),
            });
        }
        (None, None) => {
            return Err(PolicyError::NoValueForm {
                record: record.to_owned(),
                register: register.to_owned(),
            });
        }
        (Some(value), None) => value,
        (None, Some(values)) => {
            if values.len() != 1 {
                return Err(PolicyError::NotExactlyOneValue {
                    record: record.to_owned(),
                    register: register.to_owned(),
                    count: values.len(),
                });
            }
            &values[0]
        }
    };
    let bad = || PolicyError::BadValueLength {
        record: record.to_owned(),
        register: register.to_owned(),
        value: value.clone(),
        len,
    };
    if value.len() != len * 2 || value.starts_with("0x") {
        return Err(bad());
    }
    hex::decode(value).map_err(|_| bad())
}

/// Normalize a register key: a bare index (`"4"`) or a case-insensitive
/// `pcr` prefix (`"pcr4"`, `"PCR4"`), 0-23 — the spellings attested-tls's
/// `parse_azure_pcr_index` accepts.
pub(crate) fn parse_pcr_key(key: &str) -> Option<u32> {
    let digits = if key.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("pcr")) {
        &key[3..]
    } else {
        key
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok().filter(|index| *index <= 23)
}

/// Resolve one register entry to its single accepted value: exactly one of
/// `expected` / `expected_any`, binding exactly one 32-byte bare-hex value.
pub(crate) fn entry_value(record: &str, index: u32, entry: &RawEntry) -> Result<B256, PolicyError> {
    let value = match (&entry.expected, &entry.expected_any) {
        (Some(_), Some(_)) => {
            return Err(PolicyError::BothExpectedForms {
                record: record.to_owned(),
                index,
            });
        }
        (None, None) => {
            return Err(PolicyError::NoExpectedValue {
                record: record.to_owned(),
                index,
            });
        }
        (Some(single), None) => single,
        (None, Some(list)) => match list.as_slice() {
            [single] => single,
            _ => {
                return Err(PolicyError::SingleValueRequired {
                    record: record.to_owned(),
                    index,
                    count: list.len(),
                });
            }
        },
    };

    hex::decode(value)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .map(B256::from)
        .ok_or_else(|| PolicyError::BadValue {
            record: record.to_owned(),
            index,
            value: value.clone(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn b256(byte: u8) -> B256 {
        B256::from([byte; 32])
    }

    /// Two single-identity records with distinct values.
    fn two_record_policy() -> String {
        format!(
            r#"[
  {{
    "attestation_type": "azure-tdx",
    "measurement_id": "image-a",
    "measurements": {{
      "pcr4":  {{ "expected_any": ["{}"] }},
      "pcr9":  {{ "expected_any": ["{}"] }},
      "pcr11": {{ "expected_any": ["{}"] }}
    }}
  }},
  {{
    "attestation_type": "azure-tdx",
    "measurement_id": "image-b",
    "measurements": {{
      "pcr4":  {{ "expected_any": ["{}"] }},
      "pcr9":  {{ "expected_any": ["{}"] }},
      "pcr11": {{ "expected_any": ["{}"] }}
    }}
  }}
]"#,
            hex32(0x11),
            hex32(0x22),
            hex32(0x33),
            hex32(0xa1),
            hex32(0xb1),
            hex32(0xc1),
        )
    }

    #[test]
    fn compiles_a_gcp_record_under_the_gcp_schema() {
        let rtmr1 = "69b655b5c1505ef6329f853308c87d0b8e1e0161140907664302f711438212de8dc897767a07aed93af8b84377272ecc";
        let doc = format!(
            r#"[{{"attestation_type":"gcp-tdx","measurement_id":"img.tar.gz","measurements":{{"rtmr1":{{"expected":"{rtmr1}"}}}}}}]"#
        );
        let compiled = compile_policy(doc.as_bytes()).unwrap();
        let SchemaTuple::GcpTdxV1(tuple) = &compiled.records[0].tuple else {
            panic!("wrong schema");
        };
        assert_eq!(hex::encode(tuple.rtmr1), rtmr1);
        assert_eq!(compiled.records[0].tuple.schema(), GCP_TDX_V1_SCHEMA);

        let extra = doc.replace(r#""rtmr1":"#, r#""rtmr0":{"expected":"00"},"rtmr1":"#);
        assert!(matches!(
            compile_policy(extra.as_bytes()),
            Err(PolicyError::UnexpectedGcpRegister { .. })
        ));
        let mixed = format!(
            r#"[{{"attestation_type":"azure-tdx","measurement_id":"a.vhd","measurements":{{"pcr4":{{"expected":"{z}"}},"pcr9":{{"expected":"{z}"}},"pcr11":{{"expected":"{z}"}}}}}},{}]"#,
            &doc[1..doc.len() - 1],
            z = "00".repeat(32)
        );
        assert!(matches!(
            compile_policy(mixed.as_bytes()),
            Err(PolicyError::MixedAttestationTypes { .. })
        ));
    }

    #[test]
    fn compiles_one_record_to_one_id_with_record_correlation() {
        let doc = two_record_policy();
        let compiled = compile_policy(doc.as_bytes()).unwrap();

        assert_eq!(compiled.records.len(), 2);
        assert_eq!(
            compiled.records[0].tuple,
            SchemaTuple::AzureTdxV1(AzureTdxV1Measurements {
                pcr4: b256(0x11),
                pcr9: b256(0x22),
                pcr11: b256(0x33),
            })
        );
        assert_eq!(
            compiled.records[1].tuple,
            SchemaTuple::AzureTdxV1(AzureTdxV1Measurements {
                pcr4: b256(0xa1),
                pcr9: b256(0xb1),
                pcr11: b256(0xc1),
            })
        );

        // 2 unique IDs, sorted ascending, no cross-record flattening: image
        // A's pcr4 with image B's pcr9/pcr11 is not in the set.
        assert_eq!(compiled.admission_ids.len(), 2);
        assert!(compiled.admission_ids.windows(2).all(|w| w[0] < w[1]));
        let flattened = AzureTdxV1Measurements {
            pcr4: b256(0x11),
            pcr9: b256(0xb1),
            pcr11: b256(0xc1),
        };
        assert!(!compiled.admission_ids.contains(&flattened.admission_id()));
    }

    #[test]
    fn key_spellings_and_expected_forms_are_equivalent() {
        let canonical = format!(
            r#"[{{"attestation_type":"azure-tdx","measurement_id":"x","measurements":{{
                "pcr4":{{"expected_any":["{p4}"]}},
                "pcr9":{{"expected_any":["{p9}"]}},
                "pcr11":{{"expected_any":["{p11}"]}}}}}}]"#,
            p4 = hex32(0x11),
            p9 = hex32(0x22),
            p11 = hex32(0x33),
        );
        let aliased = format!(
            r#"[{{"attestation_type":"azure-tdx","measurement_id":"x","measurements":{{
                "4":{{"expected":"{p4}"}},
                "PCR9":{{"expected":"{p9}"}},
                "pcr11":{{"expected":"{p11}"}}}}}}]"#,
            p4 = hex32(0x11),
            p9 = hex32(0x22),
            p11 = hex32(0x33),
        );
        let a = compile_policy(canonical.as_bytes()).unwrap();
        let b = compile_policy(aliased.as_bytes()).unwrap();
        assert_eq!(a.admission_ids, b.admission_ids);
        // The hashes differ because the bytes differ; only the IDs normalize.
        assert_ne!(a.policy_hash, b.policy_hash);
    }

    /// Build a single-record policy with the given measurements JSON object.
    fn policy_with_measurements(measurements: &str) -> String {
        format!(
            r#"[{{"attestation_type":"azure-tdx","measurement_id":"x","measurements":{measurements}}}]"#
        )
    }

    fn valid_measurements_except(register: &str, entry: &str) -> String {
        let mut parts = vec![];
        for (name, byte) in [("pcr4", 0x11u8), ("pcr9", 0x22), ("pcr11", 0x33)] {
            if name == register {
                if !entry.is_empty() {
                    parts.push(format!(r#""{name}":{entry}"#));
                }
            } else {
                parts.push(format!(
                    r#""{name}":{{"expected_any":["{}"]}}"#,
                    hex32(byte)
                ));
            }
        }
        format!("{{{}}}", parts.join(","))
    }

    #[test]
    fn rejects_malformed_documents() {
        let cases: Vec<(String, &str)> = vec![
            ("[]".to_owned(), "Empty"),
            (
                policy_with_measurements(&valid_measurements_except("pcr11", "")),
                "MissingRegister",
            ),
            (
                policy_with_measurements(&valid_measurements_except(
                    "pcr9",
                    r#"{"expected_any":[]}"#,
                )),
                "SingleValueRequired",
            ),
            (
                policy_with_measurements(&valid_measurements_except(
                    "pcr9",
                    &format!(
                        r#"{{"expected_any":["{}","{}"]}}"#,
                        hex32(0x22),
                        hex32(0x23)
                    ),
                )),
                "SingleValueRequired",
            ),
            (
                policy_with_measurements(&valid_measurements_except("pcr9", r#"{}"#)),
                "NoExpectedValue",
            ),
            (
                policy_with_measurements(&valid_measurements_except(
                    "pcr9",
                    &format!(
                        r#"{{"expected":"{v}","expected_any":["{v}"]}}"#,
                        v = hex32(0x22)
                    ),
                )),
                "BothExpectedForms",
            ),
            (
                policy_with_measurements(&valid_measurements_except(
                    "pcr9",
                    r#"{"expected_any":["abcd"]}"#,
                )),
                "BadValue",
            ),
            (
                policy_with_measurements(&valid_measurements_except(
                    "pcr9",
                    &format!(r#"{{"expected_any":["0x{}"]}}"#, "22".repeat(31)),
                )),
                "BadValue",
            ),
            (
                // "4" and "pcr4" alias the same register.
                policy_with_measurements(&format!(
                    r#"{{"4":{{"expected_any":["{p4}"]}},"pcr4":{{"expected_any":["{p4}"]}},"pcr9":{{"expected_any":["{p9}"]}},"pcr11":{{"expected_any":["{p11}"]}}}}"#,
                    p4 = hex32(0x11),
                    p9 = hex32(0x22),
                    p11 = hex32(0x33),
                )),
                "DuplicateRegister",
            ),
            (
                // pcr8 is not part of the schema.
                policy_with_measurements(&format!(
                    r#"{{"pcr4":{{"expected_any":["{p4}"]}},"pcr8":{{"expected_any":["{p4}"]}},"pcr9":{{"expected_any":["{p9}"]}},"pcr11":{{"expected_any":["{p11}"]}}}}"#,
                    p4 = hex32(0x11),
                    p9 = hex32(0x22),
                    p11 = hex32(0x33),
                )),
                "UnexpectedRegister",
            ),
            (
                policy_with_measurements(&valid_measurements_except("pcr4", "").replacen(
                    r#""pcr9""#,
                    r#""pcr24""#,
                    1,
                )),
                "BadRegisterKey",
            ),
            (
                r#"[{"attestation_type":"dcap-tdx","measurement_id":"x","measurements":{}}]"#
                    .to_owned(),
                "UnsupportedAttestationType",
            ),
            (
                r#"[{"attestation_type":"gcp-tdx","measurement_id":"x","measurements":{}}]"#
                    .to_owned(),
                "MissingGcpRegister",
            ),
            (
                r#"[{"attestation_type":"azure-tdx","measurement_id":"x"}]"#.to_owned(),
                "Json",
            ),
            (
                policy_with_measurements(&valid_measurements_except("pcr4", "")).replacen(
                    "[{",
                    r#"[{"extra":1,"#,
                    1,
                ),
                "Json",
            ),
        ];
        for (doc, expected_variant) in cases {
            let err =
                compile_policy(doc.as_bytes()).expect_err(&format!("expected failure for {doc}"));
            let debug = format!("{err:?}");
            assert!(
                debug.starts_with(expected_variant),
                "expected {expected_variant} for {doc}, got {debug}"
            );
        }

        // Two complete records sharing one measurement_id.
        let record = format!(
            r#"{{"attestation_type":"azure-tdx","measurement_id":"x","measurements":{{"pcr4":{{"expected_any":["{p4}"]}},"pcr9":{{"expected_any":["{p9}"]}},"pcr11":{{"expected_any":["{p11}"]}}}}}}"#,
            p4 = hex32(0x11),
            p9 = hex32(0x22),
            p11 = hex32(0x33),
        );
        let doc = format!("[{record},{record}]");
        let err = compile_policy(doc.as_bytes()).unwrap_err();
        assert!(format!("{err:?}").starts_with("DuplicateMeasurementId"));
    }

    #[test]
    fn identical_tuples_across_records_dedupe_into_one_id() {
        // Two differently named images with identical measurements: legal
        // (a re-released identical build), one admission ID.
        let rec = |id: &str| {
            format!(
                r#"{{"attestation_type":"azure-tdx","measurement_id":"{id}","measurements":{{"pcr4":{{"expected_any":["{p4}"]}},"pcr9":{{"expected_any":["{p9}"]}},"pcr11":{{"expected_any":["{p11}"]}}}}}}"#,
                p4 = hex32(0x11),
                p9 = hex32(0x22),
                p11 = hex32(0x33),
            )
        };
        let doc = format!("[{},{}]", rec("image-a"), rec("image-b"));
        let compiled = compile_policy(doc.as_bytes()).unwrap();
        assert_eq!(compiled.records.len(), 2);
        assert_eq!(compiled.admission_ids.len(), 1);
    }
}
