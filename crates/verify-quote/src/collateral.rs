//! The archived form of the collateral snapshot a verification consumed.
//!
//! A founding quote is only re-verifiable for as long as the collateral it
//! was checked against is available: Intel's TCB Info, QE Identity and both
//! CRLs carry `nextUpdate` on a roughly 30-day cadence. So a founding
//! archive keeps the bundle beside the quote, and this module is the only
//! code that reads or writes the form it keeps it in.
//!
//! It keeps the instant beside the bundle. Every freshness check was
//! evaluated at that one instant, so a replay given the bundle alone
//! reproduces the verdict only by luck, and one given an instant earlier
//! than the real one will honour a certificate that was revoked after it.
//! [`CollateralSnapshot`] carries the two together, and so does the
//! document.
//!
//! It also keeps the record's `harvest_nonce`. The two files of one box sit
//! in two directories and are paired only by name, so the snapshot names
//! the record it belongs to: the nonce is minted per box and bound into the
//! quote, so no two records share one, and a replay refuses a snapshot
//! filed beside the wrong record instead of evaluating the quote at the
//! wrong instant against the wrong bundle.
//!
//! The document mirrors that: `ArchivedSnapshotV1` is the versioned
//! envelope — the instant, the nonce, and the bundle under `collateral` —
//! and `ArchivedCollateralV1` is [`QuoteCollateralV3`] field for field, in
//! the archive's own serialization:
//!
//! - the PEM chains and the raw Intel-signed JSON bodies pass through as-is,
//!   so `tcb_info` in the archive is recognisably the document Intel signed;
//! - the binary components are base64 — the two CRLs are DER, the two
//!   signatures raw ECDSA `r||s` — because `serde_json` renders their bytes
//!   as thousand-element integer arrays;
//! - `pck_certificate_chain` is absent when the fetch left it unset, which
//!   is the normal case.
//!
//! `version` sits on the envelope and decouples the committed archive from
//! `dcap-qvl`'s own struct, which may change shape across backend upgrades.
//! Parsing is strict: unknown keys are rejected, so two readers can never
//! disagree on field semantics, and the version is probed first so a future
//! envelope is reported by number rather than by its first unknown field.
//! New or changed fields require `version = 2` and an `ArchivedSnapshotV2`
//! type; a v1 document has to keep reading as v1 forever.

use anyhow::Context as _;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use seismic_attestation::{CollateralSnapshot, QuoteCollateralV3};
use serde::{Deserialize, Serialize};

/// One box's archived collateral: the snapshot its verification consumed,
/// and the `harvest_nonce` of the record it was verified with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivedSnapshot {
    pub harvest_nonce: [u8; 32],
    pub snapshot: CollateralSnapshot,
}

/// One collateral snapshot, in the form the founding archive keeps.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ArchivedSnapshotV1 {
    /// The schema number written into every document, so the file says
    /// which shape it has. This is the value on disk; [`Self::VERSION`] is
    /// the one this type reads and writes. Serde has no way to emit a
    /// constant without a field to hold it, so `render` fills it from the
    /// const and `parse` checks it against the const before anything else.
    version: u32,
    /// Seconds since the Unix epoch: the instant the verification held this
    /// bundle to, and the instant a replay has to evaluate at.
    verified_at: u64,
    /// The record's `harvest_nonce`, hex, exactly as the record spells it.
    harvest_nonce: String,
    collateral: ArchivedCollateralV1,
}

impl ArchivedSnapshotV1 {
    /// The `version` value this schema corresponds to.
    const VERSION: u32 = 1;
}

/// The DCAP collateral bundle, in the archive's own serialization.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ArchivedCollateralV1 {
    pck_crl_issuer_chain: String,
    root_ca_crl: String,
    pck_crl: String,
    tcb_info_issuer_chain: String,
    tcb_info: String,
    tcb_info_signature: String,
    qe_identity_issuer_chain: String,
    qe_identity: String,
    qe_identity_signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pck_certificate_chain: Option<String>,
}

impl From<&ArchivedSnapshot> for ArchivedSnapshotV1 {
    fn from(archived: &ArchivedSnapshot) -> Self {
        Self {
            version: Self::VERSION,
            verified_at: archived.snapshot.at,
            harvest_nonce: hex::encode(archived.harvest_nonce),
            collateral: ArchivedCollateralV1::from(&archived.snapshot.collateral),
        }
    }
}

impl TryFrom<ArchivedSnapshotV1> for ArchivedSnapshot {
    type Error = anyhow::Error;

    fn try_from(archived: ArchivedSnapshotV1) -> anyhow::Result<Self> {
        let mut harvest_nonce = [0u8; 32];
        hex::decode_to_slice(&archived.harvest_nonce, &mut harvest_nonce)
            .context("archived collateral harvest_nonce is not 32 bytes of hex")?;
        Ok(Self {
            harvest_nonce,
            snapshot: CollateralSnapshot {
                at: archived.verified_at,
                collateral: archived.collateral.try_into()?,
            },
        })
    }
}

impl From<&QuoteCollateralV3> for ArchivedCollateralV1 {
    fn from(collateral: &QuoteCollateralV3) -> Self {
        Self {
            pck_crl_issuer_chain: collateral.pck_crl_issuer_chain.clone(),
            root_ca_crl: BASE64.encode(&collateral.root_ca_crl),
            pck_crl: BASE64.encode(&collateral.pck_crl),
            tcb_info_issuer_chain: collateral.tcb_info_issuer_chain.clone(),
            tcb_info: collateral.tcb_info.clone(),
            tcb_info_signature: BASE64.encode(&collateral.tcb_info_signature),
            qe_identity_issuer_chain: collateral.qe_identity_issuer_chain.clone(),
            qe_identity: collateral.qe_identity.clone(),
            qe_identity_signature: BASE64.encode(&collateral.qe_identity_signature),
            pck_certificate_chain: collateral.pck_certificate_chain.clone(),
        }
    }
}

impl TryFrom<ArchivedCollateralV1> for QuoteCollateralV3 {
    type Error = anyhow::Error;

    fn try_from(archived: ArchivedCollateralV1) -> anyhow::Result<Self> {
        Ok(Self {
            pck_crl_issuer_chain: archived.pck_crl_issuer_chain,
            root_ca_crl: decode_base64("root_ca_crl", &archived.root_ca_crl)?,
            pck_crl: decode_base64("pck_crl", &archived.pck_crl)?,
            tcb_info_issuer_chain: archived.tcb_info_issuer_chain,
            tcb_info: archived.tcb_info,
            tcb_info_signature: decode_base64("tcb_info_signature", &archived.tcb_info_signature)?,
            qe_identity_issuer_chain: archived.qe_identity_issuer_chain,
            qe_identity: archived.qe_identity,
            qe_identity_signature: decode_base64(
                "qe_identity_signature",
                &archived.qe_identity_signature,
            )?,
            pck_certificate_chain: archived.pck_certificate_chain,
        })
    }
}

/// Render the collateral snapshot a verification consumed as the archived
/// document.
///
/// Pretty-printed with a trailing newline, matching every other file a
/// founding archive holds: this is provenance a person reads, not a wire
/// format.
pub fn render(archived: &ArchivedSnapshot) -> anyhow::Result<String> {
    let archived = ArchivedSnapshotV1::from(archived);
    Ok(serde_json::to_string_pretty(&archived).context("rendering the DCAP collateral")? + "\n")
}

/// Read one archived document back into the snapshot it holds.
pub fn parse(document: &str) -> anyhow::Result<ArchivedSnapshot> {
    // Probe the version before the strict parse: a future envelope carries
    // fields this schema does not know, and "version 2" is the actionable
    // error, not "unknown field". Failing on an unknown version rather than
    // guessing matters here — this bundle decides whether a founding quote
    // verifies.
    #[derive(Deserialize)]
    struct VersionProbe {
        version: u32,
    }
    let probe: VersionProbe =
        serde_json::from_str(document).context("parsing the archived DCAP collateral")?;
    anyhow::ensure!(
        probe.version == ArchivedSnapshotV1::VERSION,
        "archived collateral is version {}, and this build reads version {}",
        probe.version,
        ArchivedSnapshotV1::VERSION,
    );
    let archived: ArchivedSnapshotV1 =
        serde_json::from_str(document).context("parsing the archived DCAP collateral")?;
    archived.try_into()
}

/// Decode one base64 field, naming the field in the failure.
fn decode_base64(field: &str, value: &str) -> anyhow::Result<Vec<u8>> {
    BASE64
        .decode(value)
        .with_context(|| format!("archived collateral {field} is not valid base64"))
}

/// The instant the fabricated snapshot was held to. Distinct from every
/// other number in the fixture, so a field that goes missing shows up.
#[cfg(test)]
pub const FABRICATED_AT: u64 = 1_780_922_561;

/// The nonce of the record the fabricated snapshot belongs to.
#[cfg(test)]
pub const FABRICATED_NONCE: [u8; 32] = [0x5a; 32];

/// A snapshot with a distinct value per field, so a conversion that crosses
/// two fields is caught rather than cancelling out.
#[cfg(test)]
pub fn fabricated_snapshot() -> ArchivedSnapshot {
    ArchivedSnapshot {
        harvest_nonce: FABRICATED_NONCE,
        snapshot: fabricated_collateral(),
    }
}

#[cfg(test)]
pub fn fabricated_collateral() -> CollateralSnapshot {
    CollateralSnapshot {
        at: FABRICATED_AT,
        collateral: QuoteCollateralV3 {
            pck_crl_issuer_chain:
                "-----BEGIN CERTIFICATE-----\npck-crl-issuer\n-----END CERTIFICATE-----\n"
                    .to_string(),
            root_ca_crl: vec![0x30, 0x82, 0x01, 0x00],
            pck_crl: vec![0x30, 0x82, 0x02, 0x01],
            tcb_info_issuer_chain:
                "-----BEGIN CERTIFICATE-----\ntcb-info-issuer\n-----END CERTIFICATE-----\n"
                    .to_string(),
            tcb_info: r#"{"tcbInfo":{"fmspc":"90C06F000000"},"signature":"ab"}"#.to_string(),
            tcb_info_signature: vec![0xde, 0xad, 0xbe, 0xef],
            qe_identity_issuer_chain:
                "-----BEGIN CERTIFICATE-----\nqe-identity-issuer\n-----END CERTIFICATE-----\n"
                    .to_string(),
            qe_identity: r#"{"enclaveIdentity":{"id":"TD_QE"}}"#.to_string(),
            qe_identity_signature: vec![0xfe, 0xed, 0xfa, 0xce],
            pck_certificate_chain: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(snapshot: &ArchivedSnapshot) -> ArchivedSnapshot {
        parse(&render(snapshot).unwrap()).unwrap()
    }

    /// The archive has to hand the verifier back exactly what it was given,
    /// or an archived quote verifies against something other than the
    /// collateral its founding used.
    #[test]
    fn envelope_round_trips_a_snapshot_unchanged() {
        let snapshot = fabricated_snapshot();
        assert_eq!(round_trip(&snapshot), snapshot);

        let mut with_pck_chain = fabricated_snapshot();
        with_pck_chain.snapshot.collateral.pck_certificate_chain =
            Some("-----BEGIN CERTIFICATE-----\npck\n-----END CERTIFICATE-----\n".to_string());
        assert_eq!(round_trip(&with_pck_chain), with_pck_chain);
    }

    /// The instant is the half a bundle cannot supply. Losing it silently
    /// would leave a document that looks complete and replays at the wrong
    /// time, so it is asserted on its own rather than through the round trip.
    #[test]
    fn document_carries_the_instant() {
        let document = render(&fabricated_snapshot()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&document).unwrap();
        assert_eq!(value["verified_at"], FABRICATED_AT);
        assert_eq!(
            round_trip(&fabricated_snapshot()).snapshot.at,
            FABRICATED_AT
        );
    }

    /// The nonce is what pairs a snapshot with its record, in the record's
    /// own spelling so a reader can match the two files by eye.
    #[test]
    fn document_names_its_record_by_nonce() {
        let document = render(&fabricated_snapshot()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&document).unwrap();
        assert_eq!(value["harvest_nonce"], hex::encode(FABRICATED_NONCE));

        let error = parse_mutated(|value| value["harvest_nonce"] = serde_json::json!("5a5a"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("harvest_nonce"), "{error}");
    }

    /// The DER components are base64, and the Intel-signed bodies and PEM
    /// chains are the archive's own text — inspectable without tooling. The
    /// bundle sits under `collateral`, so a reader sees where Intel's
    /// material starts and the envelope ends.
    #[test]
    fn document_is_readable_and_versioned() {
        let snapshot = fabricated_snapshot();
        let expected = &snapshot.snapshot.collateral;
        let document = render(&snapshot).unwrap();
        let value: serde_json::Value = serde_json::from_str(&document).unwrap();

        assert_eq!(value["version"], 1);
        let collateral = &value["collateral"];
        assert_eq!(collateral["tcb_info"], expected.tcb_info);
        assert_eq!(collateral["qe_identity"], expected.qe_identity);
        assert_eq!(
            collateral["tcb_info_issuer_chain"],
            expected.tcb_info_issuer_chain
        );
        assert_eq!(
            collateral["root_ca_crl"],
            BASE64.encode(&expected.root_ca_crl)
        );
        // Absent rather than null when the fetch left it unset, which is the
        // normal case.
        assert!(collateral.get("pck_certificate_chain").is_none());
        assert!(document.ends_with("\n"));
    }

    /// Parse a rendered document after mutating it, the way a hand-edited or
    /// future-version archive reaches a reader.
    fn parse_mutated(
        mutate: impl FnOnce(&mut serde_json::Value),
    ) -> anyhow::Result<ArchivedSnapshot> {
        let mut value: serde_json::Value =
            serde_json::from_str(&render(&fabricated_snapshot()).unwrap()).unwrap();
        mutate(&mut value);
        parse(&serde_json::to_string(&value).unwrap())
    }

    /// A v2 envelope carries fields this schema does not know, so the version
    /// has to be reported before the strict parse trips over one of them. A
    /// future document must not be silently reinterpreted: this bundle decides
    /// whether a founding quote verifies.
    #[test]
    fn foreign_version_is_reported_before_unknown_fields() {
        let error = parse_mutated(|value| {
            value["version"] = serde_json::json!(2);
            value["some_v2_field"] = serde_json::json!("new");
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("version 2"), "{error}");
    }

    /// An unknown key at the declared version is a reader and a writer that
    /// disagree on the format, not a field to skip.
    #[test]
    fn unknown_fields_are_rejected() {
        assert!(parse_mutated(|value| value["surprise"] = serde_json::json!(1)).is_err());
        assert!(
            parse_mutated(|value| value["collateral"]["surprise"] = serde_json::json!(1)).is_err()
        );
    }

    #[test]
    fn malformed_base64_fails_by_field_name() {
        let error = parse_mutated(|value| {
            value["collateral"]["pck_crl"] = serde_json::json!("not base64!!")
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("pck_crl"), "{error}");
    }
}
