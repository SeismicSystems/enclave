//! Promotion from raw `make measure` output to a measurement-policy
//! document.
//!
//! seismic-images' measured-boot prediction carries every populated
//! register plus the event log; guest identity under a schema is only its
//! tuple. Promotion selects exactly the schema registers, normalizes their
//! spelling to the names the schema gives them, each binding a single-value
//! `expected_any`, and wraps them into one Flashbots-compatible policy
//! record. Which registers form guest identity and which value forms are
//! canonical is schema knowledge, so it lives here beside the compiler
//! rather than in deploy tooling. The full raw output remains a separate
//! build artifact for audit.
//!
//! An input that already is a record list passes through byte-verbatim:
//! the network manifest commits to the policy document's exact bytes, so
//! an already-published policy must never be re-rendered. Either way the
//! result is compiled before it is returned, so a bad promotion fails at
//! image release rather than at genesis.

use crate::policy::{RawEntry, bind_schema, compile_policy, parse_registers, schema_for};
use crate::{AZURE_TDX_ATTESTATION_TYPE, PolicyError, Register};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

/// Error label for the raw measurements map (the compiler's errors label
/// the failing policy record; promotion fails before a record exists).
const INPUT: &str = "measurements input";

/// Why raw measurements failed to promote.
#[derive(Debug, thiserror::Error)]
pub enum PromoteError {
    #[error("measurements input is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error(
        "unrecognized measurements shape: expected a make-measure object or a policy record list"
    )]
    UnrecognizedShape,
    #[error(
        "measurements input carries no measurement_id; pass one (conventionally \
         the registered image artifact filename)"
    )]
    MissingMeasurementId,
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

/// The promoted document: field order here defines the emitted bytes, which
/// the network manifest hash-commits to.
#[derive(Serialize)]
struct PromotedRecord {
    attestation_type: &'static str,
    measurement_id: String,
    measurements: PromotedMeasurements,
}

/// The schema registers in schema order, each under its own name.
struct PromotedMeasurements(Vec<(Register, PromotedEntry)>);

impl Serialize for PromotedMeasurements {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (register, entry) in &self.0 {
            map.serialize_entry(&register.to_string(), entry)?;
        }
        map.end()
    }
}

#[derive(Serialize)]
struct PromotedEntry {
    expected_any: [String; 1],
}

/// Promote raw `make measure` output into measurement-policy document bytes.
///
/// Accepts the shapes seismic-images produces — a bare register map (identity
/// metadata may sit beside the registers), or an object wrapping one under
/// `"measurements"` (extra wrapper keys such as the event log are audit
/// material and are ignored) — and emits a one-record policy
/// document binding exactly the schema registers. An input that already is a
/// record list is compiled and passed through byte-verbatim.
///
/// `measurement_id` overrides the wrapper's stamped `measurement_id`; one of
/// the two must be present, and a path is normalized to its bare filename (a
/// real artifact id never contains a separator). The wrapper's
/// `attestation_type` wins over the `attestation_type` argument, which is
/// only the default ([`AZURE_TDX_ATTESTATION_TYPE`] when `None`).
pub fn promote_measurements(
    bytes: &[u8],
    measurement_id: Option<&str>,
    attestation_type: Option<&str>,
) -> Result<Vec<u8>, PromoteError> {
    let value: Value = serde_json::from_slice(bytes)?;
    let wrapper = match value {
        Value::Array(_) => {
            compile_policy(bytes)?;
            return Ok(bytes.to_vec());
        }
        Value::Object(wrapper) => wrapper,
        _ => return Err(PromoteError::UnrecognizedShape),
    };

    let register_map = match wrapper.get("measurements") {
        Some(map) => map.clone(),
        // A bare register map may still carry stamped identity metadata
        // beside its registers; those keys are read below, not register
        // entries.
        None => Value::Object(
            wrapper
                .iter()
                .filter(|(key, _)| !matches!(key.as_str(), "measurement_id" | "attestation_type"))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        ),
    };
    let register_map: BTreeMap<String, RawEntry> = serde_json::from_value(register_map)?;

    let measurement_id = measurement_id
        .or_else(|| wrapper.get("measurement_id").and_then(Value::as_str))
        .ok_or(PromoteError::MissingMeasurementId)?;
    let measurement_id = Path::new(measurement_id)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(PromoteError::MissingMeasurementId)?;
    let attestation_type = wrapper
        .get("attestation_type")
        .and_then(Value::as_str)
        .or(attestation_type)
        .unwrap_or(AZURE_TDX_ATTESTATION_TYPE);
    let schema =
        schema_for(attestation_type).ok_or_else(|| PolicyError::UnsupportedAttestationType {
            record: INPUT.to_owned(),
            attestation_type: attestation_type.to_owned(),
        })?;

    // Registers outside the schema are dropped: their build-time inventory
    // check is release tooling's job, not policy.
    let registers = parse_registers(INPUT, &register_map, schema)?;
    let values = bind_schema(INPUT, &registers, schema)?;
    let record = PromotedRecord {
        attestation_type: schema.attestation_type,
        measurement_id: measurement_id.to_owned(),
        measurements: PromotedMeasurements(
            schema
                .registers
                .iter()
                .map(|register| {
                    let entry = PromotedEntry {
                        expected_any: [hex::encode(&values[register])],
                    };
                    (*register, entry)
                })
                .collect(),
        ),
    };
    let mut rendered = serde_json::to_string_pretty(&[record])
        .expect("promoted-record serialization is infallible");
    rendered.push('\n');
    let promoted = rendered.into_bytes();

    // The document seeds chain state; prove it compiles before it leaves the
    // promoter, so a bad promotion fails at image release, not at genesis.
    compile_policy(&promoted)?;
    Ok(promoted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile_policy;
    use alloy_primitives::B256;

    fn hex32(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    /// A make-measure wrapper: the full measured-register set plus event log.
    fn raw_wrapper() -> String {
        format!(
            r#"{{
  "measurements": {{
    "11": {{ "expected": "{p11}" }},
    "12": {{ "expected": "{zero}" }},
    "13": {{ "expected": "{zero}" }},
    "15": {{ "expected": "{zero}" }},
    "4": {{ "expected": "{p4}" }},
    "8": {{ "expected": "{zero}" }},
    "9": {{ "expected": "{p9}" }}
  }},
  "EventLog": {{ "Events": [ {{ "PCRIndex": 4, "Digest": "{p4}" }} ] }}
}}"#,
            p4 = hex32(0x11),
            p9 = hex32(0x22),
            p11 = hex32(0x33),
            zero = hex32(0x00),
        )
    }

    #[test]
    fn promotes_wrapper_to_schema_registers_only() {
        let promoted =
            promote_measurements(raw_wrapper().as_bytes(), Some("img.vhd"), None).unwrap();
        let policy: Value = serde_json::from_slice(&promoted).unwrap();
        let record = &policy.as_array().unwrap()[0];
        assert_eq!(record["measurement_id"], "img.vhd");
        assert_eq!(record["attestation_type"], "azure-tdx");
        let measurements = record["measurements"].as_object().unwrap();
        assert_eq!(
            measurements.keys().collect::<Vec<_>>(),
            ["pcr4", "pcr9", "pcr11"]
        );
        assert_eq!(
            measurements["pcr4"]["expected_any"],
            serde_json::json!([hex32(0x11)])
        );
        // The promoted document compiles to the identity the raw map states.
        let compiled = compile_policy(&promoted).unwrap();
        assert_eq!(compiled.records.len(), 1);
        let crate::SchemaTuple::AzureTdxV1(tuple) = &compiled.records[0].tuple else {
            panic!("wrong schema");
        };
        assert_eq!(tuple.pcr9, B256::from([0x22; 32]));
    }

    #[test]
    fn promotes_gcp_measurements_to_an_rtmr_record() {
        let rtmr1 = "762d5dc2b8dcd950b77ba759e2321a865a7a1fcdeb1f5d879f3e31e974c9697fa4171d92e08c2243a91af3027ad08cb0";
        let rtmr2 = "85bc309a887ad0277ea50d47aacb850d080c498e2e713eeab0d035085acbd6d47ac06f276ae4284c828dc199e6845031";
        let raw = format!(
            r#"{{"attestation_type":"gcp-tdx","measurement_id":"seismic-dev_x.tar.gz","measurements":{{"rtmr1":{{"expected":"{rtmr1}"}},"rtmr2":{{"expected":"{rtmr2}"}}}},"events":[]}}"#
        );
        let promoted = promote_measurements(raw.as_bytes(), None, None).unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&promoted).unwrap();
        assert_eq!(doc[0]["attestation_type"], "gcp-tdx");
        assert_eq!(doc[0]["measurement_id"], "seismic-dev_x.tar.gz");
        assert_eq!(
            doc[0]["measurements"]["rtmr1"]["expected_any"],
            serde_json::json!([rtmr1])
        );
        assert_eq!(
            doc[0]["measurements"]["rtmr2"]["expected_any"],
            serde_json::json!([rtmr2])
        );
        let compiled = compile_policy(&promoted).unwrap();
        assert_eq!(compiled.records[0].tuple.schema(), crate::GCP_TDX_V1_SCHEMA);

        let other = "0".repeat(96);
        let twice = raw.replace(
            r#""rtmr2":"#,
            &format!(r#""RTMR1":{{"expected":"{other}"}},"rtmr2":"#),
        );
        assert!(matches!(
            promote_measurements(twice.as_bytes(), None, None),
            Err(PromoteError::Policy(PolicyError::DuplicateRegister {
                register: Register::Rtmr(1),
                ..
            }))
        ));
    }

    #[test]
    fn promotes_bare_pcr_map_and_expected_any_values() {
        let raw = format!(
            r#"{{"pcr4":{{"expected_any":["{p4}"]}},"9":{{"expected":"{p9}"}},"pcr11":{{"expected":"{p11}"}}}}"#,
            p4 = hex32(0x11),
            p9 = hex32(0x22),
            p11 = hex32(0x33),
        );
        let promoted = promote_measurements(raw.as_bytes(), Some("img.vhd"), None).unwrap();
        compile_policy(&promoted).unwrap();
    }

    #[test]
    fn bare_pcr_map_may_carry_identity_metadata() {
        let raw = format!(
            r#"{{"measurement_id":"img.vhd","4":{{"expected":"{p4}"}},"9":{{"expected":"{p9}"}},"11":{{"expected":"{p11}"}}}}"#,
            p4 = hex32(0x11),
            p9 = hex32(0x22),
            p11 = hex32(0x33),
        );
        let promoted = promote_measurements(raw.as_bytes(), None, None).unwrap();
        let policy: Value = serde_json::from_slice(&promoted).unwrap();
        assert_eq!(policy[0]["measurement_id"], "img.vhd");
    }

    #[test]
    fn promotion_is_deterministic() {
        let a = promote_measurements(raw_wrapper().as_bytes(), Some("img.vhd"), None).unwrap();
        let b = promote_measurements(raw_wrapper().as_bytes(), Some("img.vhd"), None).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn already_promoted_list_passes_through_verbatim() {
        // Odd-but-valid formatting must survive untouched: the manifest
        // commits to these exact bytes.
        let raw = format!(
            "[ {{\"attestation_type\": \"azure-tdx\",\n\"measurement_id\": \"x\",\n  \"measurements\": {{\"4\": {{\"expected\": \"{p4}\"}}, \"9\": {{\"expected\": \"{p9}\"}}, \"11\": {{\"expected\": \"{p11}\"}}}}}} ]",
            p4 = hex32(0x11),
            p9 = hex32(0x22),
            p11 = hex32(0x33),
        );
        let promoted = promote_measurements(raw.as_bytes(), None, None).unwrap();
        assert_eq!(promoted, raw.as_bytes());
    }

    #[test]
    fn pass_through_still_compiles_the_list() {
        let err = promote_measurements(b"[]", None, None).unwrap_err();
        assert!(matches!(err, PromoteError::Policy(PolicyError::Empty)));
    }

    #[test]
    fn flag_overrides_stamped_id_and_paths_reduce_to_filenames() {
        let raw = format!(
            r#"{{"measurement_id":"stamped.vhd","measurements":{}}}"#,
            format_args!(
                r#"{{"4":{{"expected":"{p4}"}},"9":{{"expected":"{p9}"}},"11":{{"expected":"{p11}"}}}}"#,
                p4 = hex32(0x11),
                p9 = hex32(0x22),
                p11 = hex32(0x33),
            )
        );
        let stamped = promote_measurements(raw.as_bytes(), None, None).unwrap();
        let policy: Value = serde_json::from_slice(&stamped).unwrap();
        assert_eq!(policy[0]["measurement_id"], "stamped.vhd");

        let flagged =
            promote_measurements(raw.as_bytes(), Some("../images/build/img.vhd"), None).unwrap();
        let policy: Value = serde_json::from_slice(&flagged).unwrap();
        assert_eq!(policy[0]["measurement_id"], "img.vhd");
    }

    #[test]
    fn stamped_attestation_type_wins_over_default() {
        let raw = format!(
            r#"{{"attestation_type":"gcp-tdx","measurements":{{"4":{{"expected":"{p4}"}},"9":{{"expected":"{p9}"}},"11":{{"expected":"{p11}"}}}}}}"#,
            p4 = hex32(0x11),
            p9 = hex32(0x22),
            p11 = hex32(0x33),
        );
        // The stamped type selects the schema: a gcp-tdx input is promoted as
        // GCP, so PCR keys are not its register names.
        let err =
            promote_measurements(raw.as_bytes(), Some("img.vhd"), Some("azure-tdx")).unwrap_err();
        assert!(matches!(
            err,
            PromoteError::Policy(PolicyError::BadRegisterKey { .. })
        ));
    }

    #[test]
    fn rejects_malformed_inputs() {
        let p4 = hex32(0x11);
        let p9 = hex32(0x22);
        let complete = format!(
            r#""4":{{"expected":"{p4}"}},"9":{{"expected":"{p9}"}},"11":{{"expected":"{p11}"}}"#,
            p11 = hex32(0x33),
        );

        // No measurement_id anywhere.
        let raw = format!("{{{complete}}}");
        assert!(matches!(
            promote_measurements(raw.as_bytes(), None, None).unwrap_err(),
            PromoteError::MissingMeasurementId
        ));

        // A schema register missing from the raw map.
        let raw = format!(r#"{{"4":{{"expected":"{p4}"}},"9":{{"expected":"{p9}"}}}}"#);
        assert!(matches!(
            promote_measurements(raw.as_bytes(), Some("i.vhd"), None).unwrap_err(),
            PromoteError::Policy(PolicyError::MissingRegister {
                register: Register::Pcr(11),
                ..
            })
        ));

        // "4" and "pcr4" alias the same register.
        let raw = format!(r#"{{"pcr4":{{"expected":"{p4}"}},{complete}}}"#);
        assert!(matches!(
            promote_measurements(raw.as_bytes(), Some("i.vhd"), None).unwrap_err(),
            PromoteError::Policy(PolicyError::DuplicateRegister {
                register: Register::Pcr(4),
                ..
            })
        ));

        // A key that is not a PCR index.
        let raw = format!(r#"{{"mrtd":{{"expected":"{p4}"}},{complete}}}"#);
        assert!(matches!(
            promote_measurements(raw.as_bytes(), Some("i.vhd"), None).unwrap_err(),
            PromoteError::Policy(PolicyError::BadRegisterKey { .. })
        ));

        // A schema register binding a malformed value.
        let raw = format!(
            r#"{{"4":{{"expected":"abcd"}},"9":{{"expected":"{p9}"}},"11":{{"expected":"{p11}"}}}}"#,
            p11 = hex32(0x33),
        );
        assert!(matches!(
            promote_measurements(raw.as_bytes(), Some("i.vhd"), None).unwrap_err(),
            PromoteError::Policy(PolicyError::BadValue {
                register: Register::Pcr(4),
                ..
            })
        ));

        // Not a make-measure object or record list at all.
        assert!(matches!(
            promote_measurements(b"42", None, None).unwrap_err(),
            PromoteError::UnrecognizedShape
        ));
        assert!(matches!(
            promote_measurements(b"{not json", None, None).unwrap_err(),
            PromoteError::Json(_)
        ));
    }
}
