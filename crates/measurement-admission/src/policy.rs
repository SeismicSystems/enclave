//! Compiler from a measurement-policy document to the admission IDs it
//! admits.
//!
//! The document format is the Flashbots-compatible record list attested-tls
//! parses (`MeasurementPolicy::from_json_bytes`): records are ORed and
//! registers within one record are ANDed (a deprecated scalar `expected`
//! means a one-element `expected_any`). Seismic policies restrict the
//! format's per-register OR: an `expected_any` list must contain exactly one
//! value, so one record is one concrete guest identity under its schema and
//! compiles to exactly one admission ID. Any accepted set is still
//! expressible — one record per identity — and the document stays literal:
//! the identities governance reviews are the records the document lists.
//!
//! A document that seeds chain state must be exact, so this compiler is
//! deliberately stricter than attested-tls's permissive matcher: every
//! record must carry exactly the schema registers, each spelled once, each
//! binding a single digest. Parity tests hold the accepted semantics equal
//! to `check_measurement` for every document this compiler accepts.

use crate::{
    AZURE_TDX_ATTESTATION_TYPE, AZURE_TDX_V1_PCRS, AZURE_TDX_V1_SCHEMA, AdmissionId,
    AzureTdxV1Measurements, GCP_TDX_ATTESTATION_TYPE, GCP_TDX_V1_RTMRS, GCP_TDX_V1_SCHEMA,
    GcpTdxV1Measurements, Register, azure_tdx_v1_schema_id, gcp_tdx_v1_schema_id,
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
    #[error("{record}: measurement_id duplicates an earlier record's")]
    DuplicateMeasurementId { record: String },
    #[error("{record}: register key {key:?} is not {expected}")]
    BadRegisterKey {
        record: String,
        key: String,
        expected: &'static str,
    },
    #[error("{record}: register key {key:?} duplicates {register} after normalization")]
    DuplicateRegister {
        record: String,
        key: String,
        register: Register,
    },
    #[error("{record}: {register} is not an admission register of this schema")]
    UnexpectedRegister { record: String, register: Register },
    #[error("{record}: missing required register {register}")]
    MissingRegister { record: String, register: Register },
    #[error("{record}: {register} sets both expected and expected_any")]
    BothExpectedForms { record: String, register: Register },
    #[error("{record}: {register} sets neither expected nor expected_any")]
    NoExpectedValue { record: String, register: Register },
    #[error(
        "{record}: {register} must bind exactly one accepted value, got {count} \
         (one record admits one guest identity; author one record per identity)"
    )]
    SingleValueRequired {
        record: String,
        register: Register,
        count: usize,
    },
    #[error("{record}: {register} value {value:?} is not {len} bytes of bare hex")]
    BadValue {
        record: String,
        register: Register,
        value: String,
        len: usize,
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

/// How one schema spells its register keys, which registers it binds, and
/// the tuple those bind to.
pub(crate) struct Schema {
    pub(crate) attestation_type: &'static str,
    parse_key: fn(&str) -> Option<Register>,
    key_hint: &'static str,
    pub(crate) registers: &'static [Register],
    tuple: fn(&BTreeMap<Register, Vec<u8>>) -> SchemaTuple,
}

static AZURE_TDX_V1: Schema = Schema {
    attestation_type: AZURE_TDX_ATTESTATION_TYPE,
    parse_key: parse_pcr_key,
    key_hint: "a PCR index (\"4\" or \"pcr4\", 0-23)",
    registers: &[
        Register::Pcr(AZURE_TDX_V1_PCRS[0]),
        Register::Pcr(AZURE_TDX_V1_PCRS[1]),
        Register::Pcr(AZURE_TDX_V1_PCRS[2]),
    ],
    tuple: azure_tdx_v1_tuple,
};

static GCP_TDX_V1: Schema = Schema {
    attestation_type: GCP_TDX_ATTESTATION_TYPE,
    parse_key: parse_rtmr_key,
    key_hint: "an RTMR name (\"rtmr1\", 0-3)",
    registers: &[
        Register::Rtmr(GCP_TDX_V1_RTMRS[0]),
        Register::Rtmr(GCP_TDX_V1_RTMRS[1]),
    ],
    tuple: gcp_tdx_v1_tuple,
};

/// The schema an `attestation_type` compiles under.
pub(crate) fn schema_for(attestation_type: &str) -> Option<&'static Schema> {
    match attestation_type {
        AZURE_TDX_ATTESTATION_TYPE => Some(&AZURE_TDX_V1),
        GCP_TDX_ATTESTATION_TYPE => Some(&GCP_TDX_V1),
        _ => None,
    }
}

fn azure_tdx_v1_tuple(values: &BTreeMap<Register, Vec<u8>>) -> SchemaTuple {
    let pcr = |index| B256::from_slice(&values[&Register::Pcr(index)]);
    SchemaTuple::AzureTdxV1(AzureTdxV1Measurements {
        pcr4: pcr(4),
        pcr9: pcr(9),
        pcr11: pcr(11),
    })
}

fn gcp_tdx_v1_tuple(values: &BTreeMap<Register, Vec<u8>>) -> SchemaTuple {
    let rtmr = |index| {
        values[&Register::Rtmr(index)]
            .as_slice()
            .try_into()
            .expect("bound to the register's digest length")
    };
    SchemaTuple::GcpTdxV1(GcpTdxV1Measurements {
        rtmr1: rtmr(1),
        rtmr2: rtmr(2),
    })
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

        let schema = schema_for(&raw.attestation_type).ok_or_else(|| {
            PolicyError::UnsupportedAttestationType {
                record: record.clone(),
                attestation_type: raw.attestation_type.clone(),
            }
        })?;
        if !seen_measurement_ids.insert(&raw.measurement_id) {
            return Err(PolicyError::DuplicateMeasurementId { record });
        }
        let registers = parse_registers(&record, &raw.measurements, schema)?;
        if let Some(register) = registers
            .keys()
            .find(|register| !schema.registers.contains(register))
        {
            return Err(PolicyError::UnexpectedRegister {
                record,
                register: *register,
            });
        }
        let tuple = (schema.tuple)(&bind_schema(&record, &registers, schema)?);
        unique_ids.insert(tuple.admission_id());
        records.push(CompiledRecord {
            measurement_id: raw.measurement_id.clone(),
            tuple,
        });
    }

    Ok(CompiledPolicy {
        policy_hash: B256::from(<[u8; 32]>::from(Sha256::digest(bytes))),
        records,
        admission_ids: unique_ids.into_iter().collect(),
    })
}

/// The registers a measurements map names, under `schema`'s spelling of
/// keys. Two keys that normalize to one register fail: a document carrying
/// both is not reviewable as written.
pub(crate) fn parse_registers<'a>(
    record: &str,
    measurements: &'a BTreeMap<String, RawEntry>,
    schema: &Schema,
) -> Result<BTreeMap<Register, &'a RawEntry>, PolicyError> {
    let mut registers = BTreeMap::new();
    for (key, entry) in measurements {
        let register = (schema.parse_key)(key).ok_or_else(|| PolicyError::BadRegisterKey {
            record: record.to_owned(),
            key: key.clone(),
            expected: schema.key_hint,
        })?;
        if registers.insert(register, entry).is_some() {
            return Err(PolicyError::DuplicateRegister {
                record: record.to_owned(),
                key: key.clone(),
                register,
            });
        }
    }
    Ok(registers)
}

/// The single value each schema register binds; registers outside the
/// schema are ignored.
pub(crate) fn bind_schema(
    record: &str,
    registers: &BTreeMap<Register, &RawEntry>,
    schema: &Schema,
) -> Result<BTreeMap<Register, Vec<u8>>, PolicyError> {
    schema
        .registers
        .iter()
        .map(|register| {
            let entry = registers
                .get(register)
                .ok_or_else(|| PolicyError::MissingRegister {
                    record: record.to_owned(),
                    register: *register,
                })?;
            Ok((*register, entry_value(record, *register, entry)?))
        })
        .collect()
}

/// Normalize a PCR key: a bare index (`"4"`) or a case-insensitive `pcr`
/// prefix (`"pcr4"`, `"PCR4"`), 0-23 — the spellings attested-tls's
/// `parse_azure_pcr_index` accepts.
fn parse_pcr_key(key: &str) -> Option<Register> {
    let digits = if key.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("pcr")) {
        &key[3..]
    } else {
        key
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits
        .parse()
        .ok()
        .filter(|index| *index <= 23)
        .map(Register::Pcr)
}

/// Normalize an RTMR key: a case-insensitive `rtmr` prefix and one digit
/// 0-3, the names attested-tls's `DcapMeasurementRegister` accepts.
fn parse_rtmr_key(key: &str) -> Option<Register> {
    let index = key
        .get(..4)
        .filter(|prefix| prefix.eq_ignore_ascii_case("rtmr"))
        .and_then(|_| key[4..].parse::<u8>().ok())?;
    (key.len() == 5 && index <= 3).then_some(Register::Rtmr(index))
}

/// Resolve one register entry to its single accepted value: exactly one of
/// `expected` / `expected_any`, binding one bare-hex digest of the
/// register's length.
fn entry_value(record: &str, register: Register, entry: &RawEntry) -> Result<Vec<u8>, PolicyError> {
    let value = match (&entry.expected, &entry.expected_any) {
        (Some(_), Some(_)) => {
            return Err(PolicyError::BothExpectedForms {
                record: record.to_owned(),
                register,
            });
        }
        (None, None) => {
            return Err(PolicyError::NoExpectedValue {
                record: record.to_owned(),
                register,
            });
        }
        (Some(single), None) => single,
        (None, Some(list)) => match list.as_slice() {
            [single] => single,
            _ => {
                return Err(PolicyError::SingleValueRequired {
                    record: record.to_owned(),
                    register,
                    count: list.len(),
                });
            }
        },
    };

    let len = register.digest_len();
    hex::decode(value)
        .ok()
        .filter(|bytes| bytes.len() == len)
        .ok_or_else(|| PolicyError::BadValue {
            record: record.to_owned(),
            register,
            value: value.clone(),
            len,
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
        let rtmr1 = "762d5dc2b8dcd950b77ba759e2321a865a7a1fcdeb1f5d879f3e31e974c9697fa4171d92e08c2243a91af3027ad08cb0";
        let rtmr2 = "85bc309a887ad0277ea50d47aacb850d080c498e2e713eeab0d035085acbd6d47ac06f276ae4284c828dc199e6845031";
        let doc = format!(
            r#"[{{"attestation_type":"gcp-tdx","measurement_id":"img.tar.gz","measurements":{{"rtmr1":{{"expected":"{rtmr1}"}},"rtmr2":{{"expected":"{rtmr2}"}}}}}}]"#
        );
        let compiled = compile_policy(doc.as_bytes()).unwrap();
        let SchemaTuple::GcpTdxV1(tuple) = &compiled.records[0].tuple else {
            panic!("wrong schema");
        };
        assert_eq!(hex::encode(tuple.rtmr1), rtmr1);
        assert_eq!(hex::encode(tuple.rtmr2), rtmr2);
        assert_eq!(compiled.records[0].tuple.schema(), GCP_TDX_V1_SCHEMA);

        let twice = doc.replace(
            r#""rtmr2":"#,
            &format!(r#""RTMR1":{{"expected":"{rtmr1}"}},"rtmr2":"#),
        );
        assert!(matches!(
            compile_policy(twice.as_bytes()),
            Err(PolicyError::DuplicateRegister {
                register: Register::Rtmr(1),
                ..
            })
        ));

        let only_rtmr1 = doc.replace(&format!(r#","rtmr2":{{"expected":"{rtmr2}"}}"#), "");
        assert!(matches!(
            compile_policy(only_rtmr1.as_bytes()),
            Err(PolicyError::MissingRegister {
                register: Register::Rtmr(2),
                ..
            })
        ));

        let extra = doc.replace(r#""rtmr1":"#, r#""rtmr0":{"expected":"00"},"rtmr1":"#);
        assert!(matches!(
            compile_policy(extra.as_bytes()),
            Err(PolicyError::UnexpectedRegister {
                register: Register::Rtmr(0),
                ..
            })
        ));

        let not_a_register = doc.replace(r#""rtmr1":"#, r#""mrtd":{"expected":"00"},"rtmr1":"#);
        assert!(matches!(
            compile_policy(not_a_register.as_bytes()),
            Err(PolicyError::BadRegisterKey { .. })
        ));
        let mixed = format!(
            r#"[{{"attestation_type":"azure-tdx","measurement_id":"a.vhd","measurements":{{"pcr4":{{"expected":"{z}"}},"pcr9":{{"expected":"{z}"}},"pcr11":{{"expected":"{z}"}}}}}},{}]"#,
            &doc[1..doc.len() - 1],
            z = "00".repeat(32)
        );
        let compiled = compile_policy(mixed.as_bytes()).unwrap();
        assert_eq!(compiled.admission_ids.len(), 2);
        assert!(matches!(
            compiled.records[0].tuple,
            SchemaTuple::AzureTdxV1(_)
        ));
        assert!(matches!(
            compiled.records[1].tuple,
            SchemaTuple::GcpTdxV1(_)
        ));
        let report = crate::CompileReport::new(&compiled);
        assert_eq!(report.records[0].schema, crate::AZURE_TDX_V1_SCHEMA);
        assert_eq!(report.records[1].schema, GCP_TDX_V1_SCHEMA);
        assert_eq!(report.records[1].schema_id, gcp_tdx_v1_schema_id());
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
                "MissingRegister",
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
