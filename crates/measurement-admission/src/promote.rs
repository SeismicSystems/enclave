//! Promotion from raw `make measure` output to a measurement-policy
//! document.
//!
//! seismic-images' measured-boot prediction carries every populated
//! register plus the event log; guest identity under the Azure TDX v1
//! schema is only the `(pcr4, pcr9, pcr11)` tuple. Promotion selects
//! exactly the schema registers, normalizes their spelling to named
//! `pcrN` keys binding a single-value `expected_any`, and wraps them
//! into one Flashbots-compatible policy record. Which registers form
//! guest identity and which value forms are canonical is schema
//! knowledge, so it lives here beside the compiler rather than in
//! deploy tooling. The full raw output remains a separate build
//! artifact for audit.
//!
//! An input that already is a record list passes through byte-verbatim:
//! the network manifest commits to the policy document's exact bytes, so
//! an already-published policy must never be re-rendered. Either way the
//! result is compiled before it is returned, so a bad promotion fails at
//! image release rather than at genesis.

use crate::policy::{RawEntry, compile_policy, entry_value, parse_pcr_key};
use crate::{AZURE_TDX_ATTESTATION_TYPE, AZURE_TDX_V1_PCRS, PolicyError};
use alloy_primitives::B256;
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
    attestation_type: String,
    measurement_id: String,
    measurements: PromotedMeasurements,
}

#[derive(Serialize)]
struct PromotedMeasurements {
    pcr4: PromotedEntry,
    pcr9: PromotedEntry,
    pcr11: PromotedEntry,
}

#[derive(Serialize)]
struct PromotedEntry {
    expected_any: [String; 1],
}

fn promoted_entry(value: B256) -> PromotedEntry {
    PromotedEntry {
        expected_any: [hex::encode(value)],
    }
}

/// Promote raw `make measure` output into measurement-policy document bytes.
///
/// Accepts the shapes seismic-images produces — a bare PCR map (identity
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

    let pcr_map = match wrapper.get("measurements") {
        Some(map) => map.clone(),
        // A bare PCR map may still carry stamped identity metadata beside
        // its registers; those keys are read below, not register entries.
        None => Value::Object(
            wrapper
                .iter()
                .filter(|(key, _)| !matches!(key.as_str(), "measurement_id" | "attestation_type"))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        ),
    };
    let pcr_map: BTreeMap<String, RawEntry> = serde_json::from_value(pcr_map)?;

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

    // Normalize keys with the compiler's own parser, rejecting aliases that
    // collapse to one index; registers outside the schema are dropped (their
    // build-time inventory check is release tooling's job, not policy).
    let mut values: BTreeMap<u32, B256> = BTreeMap::new();
    let mut seen: Vec<u32> = Vec::new();
    for (key, entry) in &pcr_map {
        let index = parse_pcr_key(key).ok_or_else(|| PolicyError::BadRegisterKey {
            record: INPUT.to_owned(),
            key: key.clone(),
        })?;
        if seen.contains(&index) {
            return Err(PolicyError::DuplicateRegister {
                record: INPUT.to_owned(),
                key: key.clone(),
                index,
            }
            .into());
        }
        seen.push(index);
        if AZURE_TDX_V1_PCRS.contains(&index) {
            values.insert(index, entry_value(INPUT, index, entry)?);
        }
    }
    for index in AZURE_TDX_V1_PCRS {
        if !values.contains_key(&index) {
            return Err(PolicyError::MissingRegister {
                record: INPUT.to_owned(),
                index,
            }
            .into());
        }
    }

    let record = PromotedRecord {
        attestation_type: attestation_type.to_owned(),
        measurement_id: measurement_id.to_owned(),
        measurements: PromotedMeasurements {
            pcr4: promoted_entry(values[&4]),
            pcr9: promoted_entry(values[&9]),
            pcr11: promoted_entry(values[&11]),
        },
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
        assert_eq!(compiled.records[0].tuple.pcr9, B256::from([0x22; 32]));
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
        // The stamped type survives promotion and the compile-validation of
        // the output rejects it: only the supported schema promotes.
        let err =
            promote_measurements(raw.as_bytes(), Some("img.vhd"), Some("azure-tdx")).unwrap_err();
        assert!(matches!(
            err,
            PromoteError::Policy(PolicyError::UnsupportedAttestationType { .. })
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
            PromoteError::Policy(PolicyError::MissingRegister { index: 11, .. })
        ));

        // "4" and "pcr4" alias the same register.
        let raw = format!(r#"{{"pcr4":{{"expected":"{p4}"}},{complete}}}"#);
        assert!(matches!(
            promote_measurements(raw.as_bytes(), Some("i.vhd"), None).unwrap_err(),
            PromoteError::Policy(PolicyError::DuplicateRegister { index: 4, .. })
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
            PromoteError::Policy(PolicyError::BadValue { index: 4, .. })
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
