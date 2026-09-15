//! The founding archive: one node's harvest record and everything its
//! verification rested on, in one document.
//!
//! A founding quote is only re-verifiable for as long as the collateral it
//! was checked against is available: Intel's TCB Info, QE Identity and both
//! CRLs carry `nextUpdate` on a roughly 30-day cadence. So the archive keeps,
//! beside the record, the whole re-verification bundle the verification
//! handed back ([`VerificationBundle`]): the instant every freshness check
//! was evaluated at, the DCAP bundle Intel served, and digests of the trust
//! anchors compiled into the verifying build. This module is the only code
//! that reads or writes the form it keeps them in.
//!
//! One document per node, so there is nothing to pair. The earlier layout
//! kept the bundle in a sidecar file named after the record and tied to it
//! by the record's nonce, and a sidecar filed beside the wrong record was
//! caught only by a check written by hand; here the record's claims, its
//! evidence and the verification's provenance are fields of one value, and a
//! replay ([`crate::verify_archived_harvest`]) takes that value.
//!
//! The document, `version: 1`:
//!
//! - `harvest_nonce`, `node_public_key`, `consensus_public_key`: the record's
//!   claims, bare lowercase hex, exactly as the box's holder spelled them;
//!   the binding the evidence must carry is recomputed from these;
//! - `evidence`: the attestation exchange message verbatim, in the backend's
//!   own serialization;
//! - `verified_at`: seconds since the Unix epoch, the instant the
//!   verification held the bundle to and a replay evaluates at;
//! - `dcap_collateral`: [`QuoteCollateralV3`] field for field, in the
//!   archive's own serialization — the PEM chains and the raw Intel-signed
//!   JSON bodies pass through as-is, so `tcb_info` is recognisably the
//!   document Intel signed; the binary components are base64 (the two CRLs
//!   are DER, the two signatures raw ECDSA `r||s`), because `serde_json`
//!   renders their bytes as thousand-element integer arrays;
//!   `pck_certificate_chain` is absent when the fetch left it unset, which is
//!   the normal case;
//! - `trust_anchors`: the [`TrustAnchors`] of the verifying build, each Azure
//!   root by name and SHA-256 hex, and the `dcap-qvl` version;
//! - `report`: what the verification established, the binding and every
//!   quoted register; a replay checks that it reproduces this, so an edited
//!   report fails rather than misdescribing the quote.
//!
//! `version` sits on the envelope and decouples the committed archive from
//! the backend's own structs, which may change shape across upgrades.
//! Parsing is strict: unknown keys are rejected, so two readers can never
//! disagree on field semantics, and the version is probed first so a future
//! envelope is reported by number rather than by its first unknown field.
//! New or changed fields require `version = 2` and an `ArchivedFoundingV1`
//! type. The earlier unversioned record-plus-sidecar layout has no reader:
//! no committed founding carried it, and the one such artifact, this crate's
//! own real-hardware fixture, was re-encoded offline.

use crate::{QuoteRegisters, QuoteReport, TdxRegisters};
use anyhow::Context as _;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use seismic_attestation::AttestationType;
use seismic_attestation::{
    AnchorDigest, AttestationExchangeMessage, QuoteCollateralV3, TrustAnchors, VerificationBundle,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One founding node's archive: the record's claims and the verification
/// bundle that reproduces the verdict on them.
#[derive(Debug, Clone)]
pub struct FoundingArchive {
    /// The nonce the quote was requested with.
    pub harvest_nonce: [u8; 32],
    /// The ed25519 node pubkey the key holder served.
    pub node_public_key: [u8; 32],
    /// The BLS12-381 MinPk consensus pubkey the key holder served.
    pub consensus_public_key: [u8; 48],
    /// The evidence and everything the verdict on it rested on.
    pub bundle: VerificationBundle,
    /// What that verdict established; a replay has to reproduce it.
    pub report: QuoteReport,
}

impl FoundingArchive {
    /// The 64-byte `report_data` this archive's evidence must carry.
    pub fn binding(&self) -> [u8; 64] {
        crate::harvest_binding(
            &self.harvest_nonce,
            &self.node_public_key,
            &self.consensus_public_key,
        )
    }
}

/// The founding archive document, version 1.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchivedFoundingV1 {
    /// The schema number written into every document, so the file says
    /// which shape it has. This is the value on disk; [`Self::VERSION`] is
    /// the one this type reads and writes. Serde has no way to emit a
    /// constant without a field to hold it, so `render` fills it from the
    /// const and `parse` checks it against the const before anything else.
    version: u32,
    harvest_nonce: String,
    node_public_key: String,
    consensus_public_key: String,
    evidence: AttestationExchangeMessage,
    verified_at: u64,
    dcap_collateral: ArchivedCollateral,
    trust_anchors: ArchivedTrustAnchors,
    report: ArchivedReport,
}

impl ArchivedFoundingV1 {
    /// The `version` value this schema corresponds to.
    const VERSION: u32 = 1;
}

/// The DCAP collateral bundle, in the archive's own serialization.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ArchivedCollateral {
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

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ArchivedTrustAnchors {
    azure_vtpm_roots: Vec<ArchivedAnchorDigest>,
    dcap_qvl_version: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ArchivedAnchorDigest {
    name: String,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ArchivedReport {
    attestation_type: String,
    binding: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pcrs: Option<ArchivedPcrs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    registers: Option<ArchivedTdxRegisters>,
}

/// TDX measurement registers as hex, one field per register.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ArchivedTdxRegisters {
    mrtd: String,
    rtmr0: String,
    rtmr1: String,
    rtmr2: String,
    rtmr3: String,
}

/// The quoted registers as a JSON object, `pcr<N>` to hex, in register
/// order.
///
/// Hand-written serde because a `BTreeMap<String, _>` keyed `pcr<N>` sorts
/// as text (`pcr19`, `pcr2`, `pcr20`), and this document is read by people
/// and diffed across nodes. Keys are parsed here, so a key that is not
/// `pcr<N>` fails the read by name.
#[derive(Debug, PartialEq, Eq)]
struct ArchivedPcrs(BTreeMap<u32, String>);

impl Serialize for ArchivedPcrs {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (index, value) in &self.0 {
            map.serialize_entry(&format!("pcr{index}"), value)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for ArchivedPcrs {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let by_name: BTreeMap<String, String> = Deserialize::deserialize(deserializer)?;
        by_name
            .into_iter()
            .map(|(register, value)| {
                let index: u32 = register
                    .strip_prefix("pcr")
                    .and_then(|index| index.parse().ok())
                    .ok_or_else(|| {
                        D::Error::custom(format!("report.pcrs key {register:?} is not `pcr<N>`"))
                    })?;
                Ok((index, value))
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }
}

impl From<&FoundingArchive> for ArchivedFoundingV1 {
    fn from(archive: &FoundingArchive) -> Self {
        let bundle = &archive.bundle;
        Self {
            version: Self::VERSION,
            harvest_nonce: hex::encode(archive.harvest_nonce),
            node_public_key: hex::encode(archive.node_public_key),
            consensus_public_key: hex::encode(archive.consensus_public_key),
            evidence: bundle.evidence.clone(),
            verified_at: bundle.verified_at,
            dcap_collateral: ArchivedCollateral::from(&bundle.dcap_collateral),
            trust_anchors: ArchivedTrustAnchors::from(&bundle.trust_anchors),
            report: ArchivedReport::from(&archive.report),
        }
    }
}

impl TryFrom<ArchivedFoundingV1> for FoundingArchive {
    type Error = anyhow::Error;

    fn try_from(archived: ArchivedFoundingV1) -> anyhow::Result<Self> {
        Ok(Self {
            harvest_nonce: decode_hex("harvest_nonce", &archived.harvest_nonce)?,
            node_public_key: decode_hex("node_public_key", &archived.node_public_key)?,
            consensus_public_key: decode_hex(
                "consensus_public_key",
                &archived.consensus_public_key,
            )?,
            bundle: VerificationBundle {
                evidence: archived.evidence,
                verified_at: archived.verified_at,
                dcap_collateral: archived.dcap_collateral.try_into()?,
                trust_anchors: archived.trust_anchors.try_into()?,
            },
            report: archived.report.try_into()?,
        })
    }
}

impl From<&QuoteCollateralV3> for ArchivedCollateral {
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

impl TryFrom<ArchivedCollateral> for QuoteCollateralV3 {
    type Error = anyhow::Error;

    fn try_from(archived: ArchivedCollateral) -> anyhow::Result<Self> {
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

impl From<&TrustAnchors> for ArchivedTrustAnchors {
    fn from(anchors: &TrustAnchors) -> Self {
        Self {
            azure_vtpm_roots: anchors
                .azure_vtpm_roots
                .iter()
                .map(|root| ArchivedAnchorDigest {
                    name: root.name.clone(),
                    sha256: hex::encode(root.sha256),
                })
                .collect(),
            dcap_qvl_version: anchors.dcap_qvl_version.clone(),
        }
    }
}

impl TryFrom<ArchivedTrustAnchors> for TrustAnchors {
    type Error = anyhow::Error;

    fn try_from(archived: ArchivedTrustAnchors) -> anyhow::Result<Self> {
        Ok(Self {
            azure_vtpm_roots: archived
                .azure_vtpm_roots
                .into_iter()
                .map(|root| {
                    Ok(AnchorDigest {
                        sha256: decode_hex(
                            &format!("trust_anchors.azure_vtpm_roots[{}].sha256", root.name),
                            &root.sha256,
                        )?,
                        name: root.name,
                    })
                })
                .collect::<anyhow::Result<_>>()?,
            dcap_qvl_version: archived.dcap_qvl_version,
        })
    }
}

impl From<&QuoteReport> for ArchivedReport {
    fn from(report: &QuoteReport) -> Self {
        let (pcrs, registers) = match &report.registers {
            QuoteRegisters::Pcrs(pcrs) => (
                Some(ArchivedPcrs(
                    pcrs.iter()
                        .map(|(index, value)| (*index, hex::encode(value)))
                        .collect(),
                )),
                None,
            ),
            QuoteRegisters::Tdx(tdx) => (
                None,
                Some(ArchivedTdxRegisters {
                    mrtd: hex::encode(tdx.mrtd),
                    rtmr0: hex::encode(tdx.rtmr0),
                    rtmr1: hex::encode(tdx.rtmr1),
                    rtmr2: hex::encode(tdx.rtmr2),
                    rtmr3: hex::encode(tdx.rtmr3),
                }),
            ),
        };
        Self {
            attestation_type: report.attestation_type.as_str().to_string(),
            binding: hex::encode(report.binding),
            pcrs,
            registers,
        }
    }
}

impl TryFrom<ArchivedReport> for QuoteReport {
    type Error = anyhow::Error;

    fn try_from(archived: ArchivedReport) -> anyhow::Result<Self> {
        let attestation_type = match archived.attestation_type.as_str() {
            "azure-tdx" => AttestationType::AzureTdx,
            "gcp-tdx" => AttestationType::GcpTdx,
            "dcap-tdx" => AttestationType::DcapTdx,
            other => anyhow::bail!(
                "report.attestation_type {other:?} is not a platform this reader knows"
            ),
        };
        let registers = match (attestation_type, archived.pcrs, archived.registers) {
            (AttestationType::AzureTdx, Some(pcrs), None) => QuoteRegisters::Pcrs(
                pcrs.0
                    .iter()
                    .map(|(index, value)| {
                        Ok((
                            *index,
                            decode_hex(&format!("report.pcrs.pcr{index}"), value)?,
                        ))
                    })
                    .collect::<anyhow::Result<_>>()?,
            ),
            (AttestationType::GcpTdx | AttestationType::DcapTdx, None, Some(tdx)) => {
                QuoteRegisters::Tdx(Box::new(TdxRegisters {
                    mrtd: decode_hex("report.registers.mrtd", &tdx.mrtd)?,
                    rtmr0: decode_hex("report.registers.rtmr0", &tdx.rtmr0)?,
                    rtmr1: decode_hex("report.registers.rtmr1", &tdx.rtmr1)?,
                    rtmr2: decode_hex("report.registers.rtmr2", &tdx.rtmr2)?,
                    rtmr3: decode_hex("report.registers.rtmr3", &tdx.rtmr3)?,
                }))
            }
            _ => anyhow::bail!(
                "report registers do not match report.attestation_type {:?}: azure-tdx carries \
                 `pcrs`, TDX platforms carry `registers`",
                archived.attestation_type
            ),
        };
        Ok(Self {
            attestation_type,
            binding: decode_hex("report.binding", &archived.binding)?,
            registers,
        })
    }
}

/// Render one node's founding archive as the document.
///
/// Pretty-printed with a trailing newline, matching every other file a
/// network directory holds: this is provenance a person reads, not a wire
/// format.
pub fn render(archive: &FoundingArchive) -> anyhow::Result<String> {
    let archived = ArchivedFoundingV1::from(archive);
    Ok(serde_json::to_string_pretty(&archived).context("rendering the founding archive")? + "\n")
}

/// Read one archived document back into the archive it holds.
pub fn parse(document: &str) -> anyhow::Result<FoundingArchive> {
    // Probe the version before the strict parse: a future envelope carries
    // fields this schema does not know, and "version 2" is the actionable
    // error, not "unknown field". Failing on an unknown version rather than
    // guessing matters here — this document decides whether a founding quote
    // verifies.
    #[derive(Deserialize)]
    struct VersionProbe {
        version: u32,
    }
    let probe: VersionProbe =
        serde_json::from_str(document).context("parsing the founding archive")?;
    anyhow::ensure!(
        probe.version == ArchivedFoundingV1::VERSION,
        "founding archive is version {}, and this build reads version {}",
        probe.version,
        ArchivedFoundingV1::VERSION,
    );
    let archived: ArchivedFoundingV1 =
        serde_json::from_str(document).context("parsing the founding archive")?;
    archived.try_into()
}

/// Decode one base64 field, naming the field in the failure.
fn decode_base64(field: &str, value: &str) -> anyhow::Result<Vec<u8>> {
    BASE64
        .decode(value)
        .with_context(|| format!("founding archive {field} is not valid base64"))
}

/// Decode one fixed-length hex field, naming the field in the failure.
fn decode_hex<const N: usize>(field: &str, value: &str) -> anyhow::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    hex::decode_to_slice(value, &mut bytes)
        .with_context(|| format!("founding archive {field} is not {N} bytes of hex"))?;
    Ok(bytes)
}

/// The instant the fabricated bundle was held to. Distinct from every
/// other number in the fixture, so a field that goes missing shows up.
#[cfg(test)]
pub const FABRICATED_AT: u64 = 1_780_922_561;

/// An archive with a distinct value per field, so a conversion that crosses
/// two fields is caught rather than cancelling out. Its evidence declares no
/// attestation: nothing fabricated here is ever verified.
#[cfg(test)]
pub fn fabricated_archive() -> FoundingArchive {
    FoundingArchive {
        harvest_nonce: [0x5a; 32],
        node_public_key: [0x6b; 32],
        consensus_public_key: [0x7c; 48],
        bundle: VerificationBundle {
            evidence: AttestationExchangeMessage::without_attestation(),
            verified_at: FABRICATED_AT,
            dcap_collateral: fabricated_collateral(),
            trust_anchors: fabricated_anchors(),
        },
        report: QuoteReport {
            attestation_type: AttestationType::AzureTdx,
            binding: [0x8d; 64],
            registers: QuoteRegisters::Pcrs(BTreeMap::from([(4, [0x44; 32]), (11, [0xbb; 32])])),
        },
    }
}

#[cfg(test)]
pub fn fabricated_collateral() -> QuoteCollateralV3 {
    QuoteCollateralV3 {
        pck_crl_issuer_chain:
            "-----BEGIN CERTIFICATE-----\npck-crl-issuer\n-----END CERTIFICATE-----\n".to_string(),
        root_ca_crl: vec![0x30, 0x82, 0x01, 0x00],
        pck_crl: vec![0x30, 0x82, 0x02, 0x01],
        tcb_info_issuer_chain:
            "-----BEGIN CERTIFICATE-----\ntcb-info-issuer\n-----END CERTIFICATE-----\n".to_string(),
        tcb_info: r#"{"tcbInfo":{"fmspc":"90C06F000000"},"signature":"ab"}"#.to_string(),
        tcb_info_signature: vec![0xde, 0xad, 0xbe, 0xef],
        qe_identity_issuer_chain:
            "-----BEGIN CERTIFICATE-----\nqe-identity-issuer\n-----END CERTIFICATE-----\n"
                .to_string(),
        qe_identity: r#"{"enclaveIdentity":{"id":"TD_QE"}}"#.to_string(),
        qe_identity_signature: vec![0xfe, 0xed, 0xfa, 0xce],
        pck_certificate_chain: None,
    }
}

/// Anchors no build carries, so a test that expects drift gets it.
#[cfg(test)]
pub fn fabricated_anchors() -> TrustAnchors {
    TrustAnchors {
        azure_vtpm_roots: vec![
            AnchorDigest {
                name: "fabricated-root-a".to_string(),
                sha256: [0xa1; 32],
            },
            AnchorDigest {
                name: "fabricated-root-b".to_string(),
                sha256: [0xb2; 32],
            },
        ],
        dcap_qvl_version: "9.9.9".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(archive: &FoundingArchive) -> FoundingArchive {
        parse(&render(archive).unwrap()).unwrap()
    }

    /// The archive has to hand the verifier back exactly what it was given,
    /// or an archived quote verifies against something other than the
    /// collateral its founding used. The evidence type has no equality, so
    /// the document is the comparison: rendering the re-read archive has to
    /// reproduce the document byte for byte.
    #[test]
    fn envelope_round_trips_an_archive_unchanged() {
        let archive = fabricated_archive();
        let document = render(&archive).unwrap();
        let reread = parse(&document).unwrap();
        assert_eq!(render(&reread).unwrap(), document);
        assert_eq!(reread.harvest_nonce, archive.harvest_nonce);
        assert_eq!(reread.node_public_key, archive.node_public_key);
        assert_eq!(reread.consensus_public_key, archive.consensus_public_key);
        assert_eq!(reread.bundle.verified_at, archive.bundle.verified_at);
        assert_eq!(
            reread.bundle.dcap_collateral,
            archive.bundle.dcap_collateral
        );
        assert_eq!(reread.bundle.trust_anchors, archive.bundle.trust_anchors);
        assert_eq!(reread.report, archive.report);

        let mut with_pck_chain = fabricated_archive();
        with_pck_chain.bundle.dcap_collateral.pck_certificate_chain =
            Some("-----BEGIN CERTIFICATE-----\npck\n-----END CERTIFICATE-----\n".to_string());
        assert_eq!(
            round_trip(&with_pck_chain).bundle.dcap_collateral,
            with_pck_chain.bundle.dcap_collateral
        );
    }

    /// The instant is the half a bundle cannot supply. Losing it silently
    /// would leave a document that looks complete and replays at the wrong
    /// time, so it is asserted on its own rather than through the round trip.
    #[test]
    fn document_carries_the_instant() {
        let document = render(&fabricated_archive()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&document).unwrap();
        assert_eq!(value["verified_at"], FABRICATED_AT);
        assert_eq!(
            round_trip(&fabricated_archive()).bundle.verified_at,
            FABRICATED_AT
        );
    }

    /// The DER components are base64, and the Intel-signed bodies and PEM
    /// chains are the archive's own text — inspectable without tooling. The
    /// claims are bare hex in the holder's spelling, the anchors are named,
    /// and the report spells registers as the policy does.
    #[test]
    fn document_is_readable_and_versioned() {
        let archive = fabricated_archive();
        let expected = &archive.bundle.dcap_collateral;
        let document = render(&archive).unwrap();
        let value: serde_json::Value = serde_json::from_str(&document).unwrap();

        assert_eq!(value["version"], 1);
        assert_eq!(value["harvest_nonce"], "5a".repeat(32));
        assert_eq!(value["consensus_public_key"], "7c".repeat(48));
        let collateral = &value["dcap_collateral"];
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
        assert_eq!(
            value["trust_anchors"]["azure_vtpm_roots"][0]["name"],
            "fabricated-root-a"
        );
        assert_eq!(
            value["trust_anchors"]["azure_vtpm_roots"][1]["sha256"],
            "b2".repeat(32)
        );
        assert_eq!(value["trust_anchors"]["dcap_qvl_version"], "9.9.9");
        assert_eq!(value["report"]["attestation_type"], "azure-tdx");
        assert_eq!(value["report"]["pcrs"]["pcr11"], "bb".repeat(32));
        // Register order in the text, not text order: pcr4 before pcr11.
        let pcr4 = document.find("\"pcr4\"").unwrap();
        let pcr11 = document.find("\"pcr11\"").unwrap();
        assert!(pcr4 < pcr11, "{document}");
        assert!(document.ends_with("}\n"));
    }

    /// Parse a rendered document after mutating it, the way a hand-edited or
    /// future-version archive reaches a reader.
    fn parse_mutated(
        mutate: impl FnOnce(&mut serde_json::Value),
    ) -> anyhow::Result<FoundingArchive> {
        let mut value: serde_json::Value =
            serde_json::from_str(&render(&fabricated_archive()).unwrap()).unwrap();
        mutate(&mut value);
        parse(&serde_json::to_string(&value).unwrap())
    }

    /// A v2 envelope carries fields this schema does not know, so the version
    /// has to be reported before the strict parse trips over one of them. A
    /// future document must not be silently reinterpreted: this document
    /// decides whether a founding quote verifies.
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
    /// disagree on the format, not a field to skip — at every level.
    #[test]
    fn unknown_fields_are_rejected() {
        assert!(parse_mutated(|value| value["surprise"] = serde_json::json!(1)).is_err());
        assert!(
            parse_mutated(|value| value["dcap_collateral"]["surprise"] = serde_json::json!(1))
                .is_err()
        );
        assert!(
            parse_mutated(|value| value["trust_anchors"]["surprise"] = serde_json::json!(1))
                .is_err()
        );
        assert!(parse_mutated(|value| value["report"]["surprise"] = serde_json::json!(1)).is_err());
    }

    #[test]
    fn malformed_fields_fail_by_name() {
        let error = parse_mutated(|value| {
            value["dcap_collateral"]["pck_crl"] = serde_json::json!("not base64!!")
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("pck_crl"), "{error}");

        let error = parse_mutated(|value| value["harvest_nonce"] = serde_json::json!("5a5a"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("harvest_nonce"), "{error}");
        assert!(error.contains("32 bytes"), "{error}");

        let error = parse_mutated(|value| {
            value["trust_anchors"]["azure_vtpm_roots"][0]["sha256"] = serde_json::json!("zz")
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("fabricated-root-a"), "{error}");

        // A bad register name fails inside serde, under the parse context.
        let error = format!(
            "{:#}",
            parse_mutated(|value| value["report"]["pcrs"] = serde_json::json!({"register4": "44"}))
                .unwrap_err()
        );
        assert!(error.contains("register4"), "{error}");

        let error = parse_mutated(|value| {
            value["report"]["attestation_type"] = serde_json::json!("gcp-tdx")
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("gcp-tdx"), "{error}");
    }
}
