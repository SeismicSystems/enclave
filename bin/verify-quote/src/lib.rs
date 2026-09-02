//! Relying-party verification of Seismic node quotes.
//!
//! Two checks, sharing one DCAP verification path (`seismic-attestation` over
//! the complete evidence envelope, enforcing the measurement policy). They
//! differ only in which binding they recompute and where the evidence comes
//! from:
//!
//! - [`verify_harvest`] checks one founding node's summit-keys harvest quote,
//!   taking that node's whole harvest record (see [`HarvestRecord`]): the
//!   record's evidence must carry
//!   `founding_summit_keys_binding(harvest_nonce, node_public_key,
//!   consensus_public_key)` over the record's own claims. The record is per
//!   node, so one call covers one node's harvest.
//! - [`verify_deploy`] checks a freshly provisioned node before the operator
//!   relies on it (publishing its address, handing it out as a bootnode): it
//!   mints a fresh `deployment_nonce`, requests evidence from the node's
//!   attestation service (`getDeployVerificationEvidence`), and recomputes
//!   `deploy_verification_binding(network_id, nonce)` from the caller's own
//!   copy of the network manifest.
//!
//! A harvest is judged against the collateral its caller chooses, and both
//! choices matter (see [`HarvestCollateral`]): a live verification fetches
//! Intel's bundle and judges at the wall clock, and hands back the bundle it
//! consumed so an archive can keep it ([`VerifiedHarvest::archived_collateral`]);
//! a replay is given an archived bundle and the instant it was held to, and
//! reaches no collateral service at all. Intel's TCB Info, QE Identity and both
//! CRLs carry `nextUpdate` on a roughly 30-day cadence, so the replay is the
//! only mode under which a founding quote still verifies a month after the
//! founding.
//!
//! A measurement policy is required throughout: there is no accept-any entry
//! point, because the measurement check is the point.
//!
//! Verification-only: nothing here touches a local TPM. Azure TDX verification
//! is pure computation over the evidence bytes (the `azure-verifier` feature of
//! the `attestation` backend), so it builds and runs anywhere, including macOS;
//! [`verify_deploy`] additionally makes one JSON-RPC request to the target node.

pub mod collateral;

use anyhow::Context as _;
use jsonrpsee::http_client::HttpClientBuilder;
use seismic_attestation::{
    AttestationType, VerifiedAzureAttestation, VerifiedEvidence, VerifiedSeismicAttestation,
    VerifyMode, VerifyOptions,
    bindings::{
        binding64_from_digest32, deploy_verification_binding, founding_summit_keys_binding,
    },
    verify_evidence_with_policy,
};
use seismic_attestation_rpc::AttestationRpcClient as _;
use serde::Deserialize;
use std::{collections::BTreeMap, time::Duration};

pub use collateral::ArchivedSnapshot;
pub use seismic_attestation::{
    AttestationExchangeMessage, CollateralSnapshot, NetworkId, NetworkManifestV1,
    SeismicMeasurementPolicy,
};

/// How long a node gets to answer a deploy-verification challenge. Quote
/// generation opens the node's TPM exclusively and is serialized in-process,
/// so a busy node answers in seconds, not milliseconds.
const QUOTE_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// One founding node's harvest record: the four facts a harvest quote is
/// verified against, in one JSON document.
///
/// This is the founding harvest archive's schema, and what makes the archive
/// re-verifiable: deploy writes one such document per node when it collects
/// the keys, and anyone re-checking the founding set later hands the same file
/// straight back to [`verify_harvest`]. What the archive keeps alongside these
/// fields (when the harvest ran, the report of the verification that passed) is
/// ignored here, so an archived file verifies as-is.
///
/// The three claims are untrusted input: the quote's `report_data` is what
/// decides whether the node's keys really are these, so a wrong claim surfaces
/// as a binding mismatch.
#[derive(Debug, Deserialize)]
pub struct HarvestRecord {
    /// The nonce the quote was requested with (32 bytes hex).
    pub harvest_nonce: String,

    /// The ed25519 node pubkey the key holder served (32 bytes hex).
    pub node_public_key: String,

    /// The BLS12-381 MinPk consensus pubkey the key holder served
    /// (48 bytes hex).
    pub consensus_public_key: String,

    /// The evidence the key holder served, verbatim.
    pub evidence: AttestationExchangeMessage,
}

/// Where the DCAP collateral a harvest is judged against comes from.
///
/// Capture and replay are the two ends of a founding archive, and they exclude
/// each other by construction: a replay reaches no collateral service, so there
/// is nothing left for a PCCS to serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HarvestCollateral {
    /// Fetch Intel's bundle and judge the quote at the wall clock, optionally
    /// from `pccs_url` instead of the backend's default provider.
    Live { pccs_url: Option<String> },

    /// Replay against an archived snapshot, at the instant it was held to,
    /// reaching no collateral service. Boxed: a bundle of Intel's material is
    /// far larger than the other choice, which is a URL at most.
    Archived(Box<ArchivedSnapshot>),
}

impl Default for HarvestCollateral {
    fn default() -> Self {
        Self::Live { pccs_url: None }
    }
}

/// What a passing verification proves, whatever its purpose: the `report_data`
/// the quote carried — recomputed by the verifier and matched — and every
/// register the quote attests.
///
/// Every quoted register is carried, not just the ones the policy pins,
/// because the caller keeps this as provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteReport {
    /// The 64-byte `report_data` bound into the quote.
    pub binding: [u8; 64],

    /// Every register the quote covers, in register order.
    pub pcrs: BTreeMap<u32, [u8; 32]>,
}

impl QuoteReport {
    fn from_verified(verified: &VerifiedAzureAttestation) -> Self {
        Self {
            binding: verified.binding,
            // Register order, so archived reports diff cleanly across nodes,
            // boots and builds: the backend hands back a `HashMap`, whose
            // iteration order is not stable.
            pcrs: verified
                .guest_measurements
                .pcrs
                .iter()
                .map(|(index, value)| (*index, *value))
                .collect(),
        }
    }

    /// This report as a JSON object.
    pub fn to_json(&self) -> serde_json::Value {
        let pcrs: serde_json::Map<String, serde_json::Value> = self
            .pcrs
            .iter()
            .map(|(index, value)| (format!("pcr{index}"), hex::encode(value).into()))
            .collect();
        serde_json::json!({
            "verified": true,
            "attestation_type": AttestationType::AzureTdx.as_str(),
            "binding": hex::encode(self.binding),
            "pcrs": pcrs,
        })
    }
}

/// A verified harvest quote, and the collateral the verdict depended on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHarvest {
    /// What the quote proved.
    pub report: QuoteReport,

    /// The record's `harvest_nonce`: what names the record this verification
    /// belongs to.
    pub harvest_nonce: [u8; 32],

    /// The DCAP collateral this verification consumed — Intel's bundle and the
    /// instant it was held to.
    pub collateral: CollateralSnapshot,
}

impl VerifiedHarvest {
    /// This verification's report as a JSON object.
    pub fn to_json(&self) -> serde_json::Value {
        self.report.to_json()
    }

    /// The archived-collateral document for this verification: the exact bundle
    /// the verdict depended on, naming the record it was verified with.
    ///
    /// The caller owns the layout and writes these bytes verbatim. They are
    /// read back here before they leave this process: nothing parses them again
    /// until a re-verification that may be a year away, so a snapshot that does
    /// not round-trip has to fail the harvest that produced it.
    pub fn archived_collateral(&self) -> anyhow::Result<String> {
        let archived = ArchivedSnapshot {
            harvest_nonce: self.harvest_nonce,
            snapshot: self.collateral.clone(),
        };
        let document = collateral::render(&archived)?;
        let reread =
            collateral::parse(&document).context("re-reading the rendered DCAP collateral")?;
        anyhow::ensure!(
            reread == archived,
            "the rendered DCAP collateral does not read back as the collateral this \
             verification used"
        );
        Ok(document)
    }
}

/// A verified deploy-verification challenge, and the facts of what was checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDeploy {
    /// What the quote proved.
    pub report: QuoteReport,

    /// The network identity the binding committed to.
    pub network_id: NetworkId,

    /// The nonce that made this run's quote fresh.
    pub deployment_nonce: [u8; 32],
}

impl VerifiedDeploy {
    /// This verification's report as a JSON object, carrying the
    /// purpose-specific facts of what was checked alongside what the quote
    /// proved.
    pub fn to_json(&self) -> serde_json::Value {
        let mut object = self.report.to_json();
        let map = object.as_object_mut().expect("a report is a JSON object");
        map.insert("network_id".to_string(), self.network_id.to_string().into());
        map.insert(
            "deployment_nonce".to_string(),
            hex::encode(self.deployment_nonce).into(),
        );
        object
    }
}

/// Verify one founding node's summit-keys harvest quote against `policy`.
///
/// The record's claims decide the binding: the quote must carry
/// `founding_summit_keys_binding` over this record's nonce and both pubkeys, so
/// a record claiming keys the node never quoted fails as a binding mismatch.
///
/// A [`HarvestCollateral::Archived`] snapshot has to be the one this record's
/// verification produced, and is refused otherwise. The instant decides which
/// validity and revocation windows are open, so a snapshot filed beside another
/// box's record would evaluate the quote at the wrong instant against the wrong
/// bundle. Neither file is signed, so this is not a trust boundary; it catches
/// the mispairing an archive comes to by accident, exactly, since no two records
/// share a nonce.
pub async fn verify_harvest(
    record: HarvestRecord,
    policy: SeismicMeasurementPolicy,
    collateral: HarvestCollateral,
) -> anyhow::Result<VerifiedHarvest> {
    // Resolve everything that can fail on a malformed record before any
    // verification: DCAP costs collateral round-trips, so a bad field should
    // not be discovered on the far side of them.
    let nonce = decode_hex_field::<32>("harvest_nonce", &record.harvest_nonce)?;
    let node_pk = decode_hex_field::<32>("node_public_key", &record.node_public_key)?;
    let consensus_pk =
        decode_hex_field::<48>("consensus_public_key", &record.consensus_public_key)?;
    let binding = harvest_binding(&nonce, &node_pk, &consensus_pk);

    let (mode, pccs_url) = match collateral {
        HarvestCollateral::Live { pccs_url } => (VerifyMode::Live, pccs_url),
        HarvestCollateral::Archived(archived) => {
            anyhow::ensure!(
                archived.harvest_nonce == nonce,
                "the archived collateral belongs to the record with harvest_nonce {}, not to \
                 this one ({}): they are not from one harvest",
                hex::encode(archived.harvest_nonce),
                hex::encode(nonce),
            );
            (VerifyMode::Archived(archived.snapshot), None)
        }
    };

    let (verified, collateral) = verify_azure(record.evidence, binding, policy, mode, pccs_url)
        .await
        .context("verifying harvest evidence")?;
    Ok(VerifiedHarvest {
        report: QuoteReport::from_verified(&verified),
        harvest_nonce: nonce,
        collateral,
    })
}

/// Challenge the node serving `endpoint` and verify its answer against
/// `policy`, for the network `manifest_bytes` names.
///
/// A pass proves a measured node holding this manifest answered this exact
/// request. The check protects only the operator's own decisions: membership in
/// the network is granted by the network's own gates (the attested root-key
/// handshake and its admission policy), never by this check.
///
/// `manifest_bytes` are the exact `network-manifest.json` bytes the node is
/// expected to have booted with — the network identity the binding commits to
/// is their hash. They are strictly parsed first, which is what separates "you
/// passed the wrong file" from "this node answered for another network":
/// without the parse, any file hashes to some id and the run fails as a binding
/// mismatch — the alarm that makes an operator burn a box.
pub async fn verify_deploy(
    endpoint: &str,
    manifest_bytes: &[u8],
    policy: SeismicMeasurementPolicy,
    pccs_url: Option<String>,
) -> anyhow::Result<VerifiedDeploy> {
    NetworkManifestV1::from_json_bytes(manifest_bytes)
        .context("the manifest is not a v1 network manifest")?;
    let network_id = NetworkId::from_manifest_bytes(manifest_bytes);

    let client = HttpClientBuilder::default()
        .request_timeout(QUOTE_REQUEST_TIMEOUT)
        .build(endpoint)
        .with_context(|| format!("endpoint {endpoint} is not a usable URL"))?;

    // Minted here and never handed to anyone but the node under test, so the
    // returned quote can only answer this exact request.
    let deployment_nonce: [u8; 32] = rand::random();
    let response = client
        .get_deploy_verification_evidence(deployment_nonce)
        .await
        .with_context(|| format!("requesting deploy-verification evidence from {endpoint}"))?;

    let binding = deploy_binding(&network_id, &deployment_nonce);
    // The collateral goes unarchived here: a live challenge is fresh evidence,
    // judged against fresh collateral at the wall clock.
    let (verified, _collateral) = verify_azure(
        response.evidence,
        binding,
        policy,
        VerifyMode::Live,
        pccs_url,
    )
    .await
    .context("verifying deploy-verification evidence")?;
    Ok(VerifiedDeploy {
        report: QuoteReport::from_verified(&verified),
        network_id,
        deployment_nonce,
    })
}

/// The 64-byte `report_data` a harvested quote must carry.
///
/// Pure and deliberately trivial: this one line is the single definition of the
/// check, linked by everything that verifies a harvest.
pub fn harvest_binding(nonce: &[u8; 32], node_pk: &[u8; 32], consensus_pk: &[u8; 48]) -> [u8; 64] {
    binding64_from_digest32(founding_summit_keys_binding(nonce, node_pk, consensus_pk))
}

/// The 64-byte `report_data` a deploy-verification quote must carry
/// (same single-definition rationale as [`harvest_binding`]).
pub fn deploy_binding(network_id: &NetworkId, deployment_nonce: &[u8; 32]) -> [u8; 64] {
    binding64_from_digest32(deploy_verification_binding(network_id, deployment_nonce))
}

/// Verify Azure TDX evidence against `binding` and `policy`, returning the
/// verified output and the DCAP collateral the verification consumed.
///
/// Wrong-platform evidence is rejected on the claimed type, before
/// verification: DCAP verification costs collateral round-trips, and this
/// policy format cannot pin a non-Azure platform's measurements anyway.
async fn verify_azure(
    evidence: AttestationExchangeMessage,
    binding: [u8; 64],
    policy: SeismicMeasurementPolicy,
    mode: VerifyMode,
    pccs_url: Option<String>,
) -> anyhow::Result<(VerifiedAzureAttestation, CollateralSnapshot)> {
    anyhow::ensure!(
        evidence.attestation_type() == AttestationType::AzureTdx,
        "expected {} evidence, got {}",
        AttestationType::AzureTdx.as_str(),
        evidence.attestation_type().as_str(),
    );

    let VerifiedEvidence {
        attestation,
        collateral,
    } = verify_evidence_with_policy(
        evidence,
        binding,
        policy,
        VerifyOptions {
            mode,
            pccs_url,
            dump_dcap_quotes: false,
        },
    )
    .await?;
    let VerifiedSeismicAttestation::AzureTdx(verified) = attestation else {
        anyhow::bail!(
            "verified output is not azure-tdx despite azure-tdx evidence: {attestation:?}"
        );
    };
    Ok((verified, collateral))
}

/// Decode one fixed-length hex field of the record, naming the field in every
/// failure.
///
/// A field of the wrong length or spelling is a malformed record, not a failed
/// quote, and the two look alike once the binding is computed — so each is
/// rejected up front, by name.
fn decode_hex_field<const N: usize>(field: &str, value: &str) -> anyhow::Result<[u8; N]> {
    let bare = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(bare).with_context(|| format!("record {field} is not valid hex"))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            "record {field} must be {N} bytes ({} hex chars), got {}",
            N * 2,
            bytes.len()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use seismic_attestation::AzureGuestMeasurements;
    use std::collections::HashMap;

    /// One real founding, kept verbatim: a harvest record, the collateral
    /// snapshot its verification consumed, and the promoted policy it was
    /// verified against. Captured on Azure TDX hardware from cohort
    /// `tmp-devnet-1` on image `seismic-dev_2026-08-27.5c012e.vhd`,
    /// harvested 2026-08-27T20:20:55Z and torn down the same day. The
    /// pubkeys are a destroyed throwaway network's, so the committed archive
    /// discloses nothing.
    const FOUNDING_RECORD: &str = include_str!("../fixtures/founding-record-v1.json");
    const FOUNDING_COLLATERAL: &str = include_str!("../fixtures/founding-collateral-v1.json");
    const FOUNDING_POLICY: &str = include_str!("../fixtures/founding-policy-v1.json");

    /// The instant frozen into that snapshot, and the reason the fixture
    /// cannot rot: a replay evaluates every freshness window here, not at
    /// the wall clock.
    const FOUNDING_VERIFIED_AT: u64 = 1787862055;

    /// How many registers the Azure TDX v1 admission schema
    /// (`seismic.azure-tdx.pcr4-pcr9-pcr11.v1`) pins: guest identity is that
    /// tuple and nothing else, so a promoted policy carries exactly three.
    const AZURE_TDX_V1_REGISTERS: usize = 3;

    /// How many registers an Azure vTPM quote attests: PCRs 0-23, all
    /// covered by the signed `pcrDigest` whether or not a policy pins them.
    const AZURE_VTPM_REGISTERS: usize = 24;

    const NONCE_HEX: &str = "7777777777777777777777777777777777777777777777777777777777777777";
    const NODE_PK_HEX: &str = "8888888888888888888888888888888888888888888888888888888888888888";
    const CONSENSUS_PK_HEX: &str = "999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999";

    /// A policy that parses. Its measurements never get checked in the
    /// fabricated cases: those fail before verification, which is the point —
    /// no test here reaches live DCAP.
    const VALID_POLICY: &str = r#"[
      {
        "attestation_type": "azure-tdx",
        "measurement_id": "verify-quote-test.vhd",
        "measurements": {
          "pcr4": { "expected_any": ["d57063c0669599b885c43a0683436a3463ad49513ddb3996e6fc96040508fd8e"] }
        }
      }
    ]"#;

    fn policy(document: &str) -> SeismicMeasurementPolicy {
        SeismicMeasurementPolicy::from_json_bytes(document.as_bytes()).expect("policy document")
    }

    fn record(document: &str) -> HarvestRecord {
        serde_json::from_str(document).expect("harvest record")
    }

    /// A harvest record carrying `evidence` verbatim, with the frozen claims
    /// the binding vectors use.
    fn record_json(evidence: &str) -> String {
        format!(
            r#"{{
              "harvest_nonce": "{NONCE_HEX}",
              "node_public_key": "{NODE_PK_HEX}",
              "consensus_public_key": "{CONSENSUS_PK_HEX}",
              "evidence": {evidence}
            }}"#
        )
    }

    /// The registers a policy document pins, and the single value each
    /// demands, read straight out of the JSON.
    fn policy_registers(document: &str) -> BTreeMap<String, String> {
        let records: serde_json::Value = serde_json::from_str(document).expect("policy document");
        records[0]["measurements"]
            .as_object()
            .expect("a measurements map")
            .iter()
            .map(|(register, entry)| {
                let values = entry["expected_any"].as_array().expect("expected_any");
                assert_eq!(values.len(), 1, "{register} pins more than one value");
                (
                    register.clone(),
                    values[0].as_str().expect("hex").to_string(),
                )
            })
            .collect()
    }

    /// The property the founding archive exists for, over real hardware
    /// evidence: a founding quote re-verifies against its own archived
    /// collateral, reaching no collateral service and depending in no way on
    /// when the test runs.
    ///
    /// Every other offline test here runs on fabricated collateral, which
    /// exercises the plumbing but never a bundle Intel actually served. This
    /// one holds the whole path to real material — the DCAP chain, the TCB
    /// Info and QE Identity windows, both CRLs, and the Azure AK certificate
    /// chain — at the instant the snapshot pins. A live verification of this
    /// same record stops passing once the bundle's `nextUpdate` lapses
    /// (2026-09-26); this one keeps passing, which is the whole point.
    #[tokio::test]
    async fn a_real_founding_reverifies_offline_against_its_archived_collateral() {
        // Asserted before verifying: a fixture re-captured without its
        // instant should fail here, not as a puzzling expiry years from now.
        let archived = collateral::parse(FOUNDING_COLLATERAL).expect("archived snapshot");
        assert_eq!(archived.snapshot.at, FOUNDING_VERIFIED_AT);

        let verified = verify_harvest(
            record(FOUNDING_RECORD),
            policy(FOUNDING_POLICY),
            HarvestCollateral::Archived(Box::new(archived)),
        )
        .await
        .expect("the archived founding verifies offline");

        let report = verified.to_json();
        assert_eq!(report["verified"], true);
        assert_eq!(report["attestation_type"], "azure-tdx");

        // The policy has to be one that really pins this guest: a policy
        // whose measurements map were empty accepts any quote, and this test
        // would pass while checking nothing. So every register it pins must
        // come back with the value it demanded.
        let pinned = policy_registers(FOUNDING_POLICY);
        assert_eq!(pinned.len(), AZURE_TDX_V1_REGISTERS, "{pinned:?}");
        let pcrs = report["pcrs"].as_object().unwrap();
        for (register, expected) in &pinned {
            assert_eq!(pcrs[register], *expected, "{register}");
        }
        // And the rest ride along as provenance, pinned by the same signed
        // pcrDigest but constrained by no policy.
        assert_eq!(pcrs.len(), AZURE_VTPM_REGISTERS);
    }

    /// The other half of the same property: the pinned instant is what makes
    /// that founding verify, not the bundle alone. Move the instant past the
    /// bundle's `nextUpdate` and the very same record and snapshot stop
    /// verifying — which is what a live verification will do to this record
    /// from 2026-09-26 on, and what the archive exists to avoid.
    #[tokio::test]
    async fn the_archived_instant_is_what_makes_the_founding_verify() {
        // 2027-01-15, months past every window in the archived bundle. Only
        // the instant changes; the collateral is the same bytes that verify
        // in the test above.
        let mut document: serde_json::Value = serde_json::from_str(FOUNDING_COLLATERAL).unwrap();
        document["verified_at"] = serde_json::json!(1_800_000_000u64);
        let archived = collateral::parse(&document.to_string()).expect("archived snapshot");

        let error = verify_harvest(
            record(FOUNDING_RECORD),
            policy(FOUNDING_POLICY),
            HarvestCollateral::Archived(Box::new(archived)),
        )
        .await
        .expect_err("an expired bundle must not verify");
        assert!(
            format!("{error:#}").contains("DCAP"),
            "expected a DCAP freshness failure, got: {error:#}"
        );
    }

    /// The instant decides which validity and revocation windows are open, so
    /// a snapshot has to be the one this record's verification produced. The
    /// snapshot names its record by nonce, and no two records share one, so
    /// a snapshot filed beside another box's record is refused exactly —
    /// before any verification, since the pairing is what decides whether the
    /// bundle applies at all.
    #[tokio::test]
    async fn replay_pairs_a_snapshot_with_its_record_by_nonce() {
        let error = verify_harvest(
            record(&record_json(NO_ATTESTATION)),
            policy(VALID_POLICY),
            HarvestCollateral::Archived(Box::new(collateral::fabricated_snapshot())),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("not from one harvest"), "{error}");
        assert!(error.contains(NONCE_HEX), "{error}");
        assert!(
            error.contains(&hex::encode(collateral::FABRICATED_NONCE)),
            "{error}"
        );
    }

    const NO_ATTESTATION: &str = r#"{ "attestation_type": "none", "attestation": [] }"#;

    /// One job, one binding: a quote from a platform whose measurements this
    /// policy format cannot pin is rejected without any collateral fetching.
    #[tokio::test]
    async fn non_azure_evidence_is_rejected() {
        let error = verify_harvest(
            record(&record_json(NO_ATTESTATION)),
            policy(VALID_POLICY),
            HarvestCollateral::default(),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("expected azure-tdx evidence"),
            "{error:#}"
        );
    }

    /// The archived document a verification hands back names the record it was
    /// verified with, so the snapshot a harvest archives is the one its own
    /// replay accepts.
    #[test]
    fn the_archived_document_names_the_record_it_verified() {
        let nonce = [0x3cu8; 32];
        let verified = VerifiedHarvest {
            report: QuoteReport {
                binding: [0u8; 64],
                pcrs: BTreeMap::new(),
            },
            harvest_nonce: nonce,
            collateral: collateral::fabricated_collateral(),
        };

        let archived = collateral::parse(&verified.archived_collateral().unwrap()).unwrap();
        assert_eq!(archived.harvest_nonce, nonce);
        assert_eq!(archived.snapshot, collateral::fabricated_collateral());
    }

    /// The bindings are wire-format commitments shared with the quoting node,
    /// so these vectors are frozen: each is its `bindings.rs` frozen digest,
    /// zero-padded to 64 bytes.
    #[test]
    fn bindings_match_frozen_vectors() {
        let harvest = harvest_binding(&[0x77; 32], &[0x88; 32], &[0x99; 48]);
        assert_eq!(
            hex::encode(&harvest[..32]),
            "8973b984dc10f809ebfaacdcad64b8cc5a647cf24e4bc27b3833cc234a9290e5"
        );
        assert_eq!(&harvest[32..], &[0u8; 32]);

        let deploy = deploy_binding(&NetworkId::from_bytes([0x11; 32]), &[0x66; 32]);
        assert_eq!(
            hex::encode(&deploy[..32]),
            "16a53bcb2d1421951a830a1308bca525b8ecfbf96fc89ad6152cdbfce4777eb9"
        );
        assert_eq!(&deploy[32..], &[0u8; 32]);
    }

    /// The record's hex fields feed the binding, and a wrong one produces a
    /// mismatch that looks exactly like a bad quote — so they are rejected up
    /// front, by name.
    #[test]
    fn hex_fields_fail_by_field_name() {
        let not_hex = decode_hex_field::<32>("harvest_nonce", "zz77")
            .unwrap_err()
            .to_string();
        assert!(not_hex.contains("harvest_nonce"), "{not_hex}");

        let wrong_length = decode_hex_field::<48>("consensus_public_key", NODE_PK_HEX)
            .unwrap_err()
            .to_string();
        assert!(
            wrong_length.contains("consensus_public_key"),
            "{wrong_length}"
        );
        assert!(wrong_length.contains("48 bytes"), "{wrong_length}");

        assert_eq!(
            decode_hex_field::<32>("node_public_key", NODE_PK_HEX).unwrap(),
            [0x88; 32]
        );
        // The archive writes bare hex; 0x-prefixed means the same key.
        assert_eq!(
            decode_hex_field::<32>("node_public_key", &format!("0x{NODE_PK_HEX}")).unwrap(),
            [0x88; 32]
        );
    }

    /// The archived record is the input format: a file carrying the harvest's
    /// own provenance fields around the four verified ones parses as-is.
    #[test]
    fn record_ignores_the_archives_extra_fields() {
        let archived = format!(
            r#"{{
              "harvest_nonce": "{NONCE_HEX}",
              "node_public_key": "{NODE_PK_HEX}",
              "consensus_public_key": "{CONSENSUS_PK_HEX}",
              "evidence": {{ "attestation_type": "azure-tdx", "attestation": [1, 2, 3] }},
              "harvested_at": "2026-08-04T00:00:00+00:00",
              "verification": {{ "verified": true, "pcrs": {{}} }}
            }}"#
        );
        let record = record(&archived);

        assert_eq!(
            decode_hex_field::<32>("harvest_nonce", &record.harvest_nonce).unwrap(),
            [0x77; 32]
        );
        assert_eq!(
            decode_hex_field::<48>("consensus_public_key", &record.consensus_public_key).unwrap(),
            [0x99; 48]
        );
    }

    #[test]
    fn report_carries_every_quoted_register() {
        let verified = VerifiedAzureAttestation {
            binding: harvest_binding(&[0x77; 32], &[0x88; 32], &[0x99; 48]),
            guest_measurements: AzureGuestMeasurements {
                pcrs: HashMap::from([(11, [0xbb; 32]), (4, [0x44; 32]), (9, [0x99; 32])]),
            },
        };

        let report = QuoteReport::from_verified(&verified).to_json();

        assert_eq!(report["verified"], true);
        assert_eq!(report["attestation_type"], "azure-tdx");
        assert_eq!(
            report["binding"],
            format!(
                "8973b984dc10f809ebfaacdcad64b8cc5a647cf24e4bc27b3833cc234a9290e5{}",
                "00".repeat(32)
            )
        );
        // Not just the policy's registers: the caller archives this as harvest
        // provenance.
        let pcrs = report["pcrs"].as_object().unwrap();
        assert_eq!(pcrs.len(), 3);
        assert_eq!(pcrs["pcr4"], "44".repeat(32));
        assert_eq!(pcrs["pcr9"], "99".repeat(32));
        assert_eq!(pcrs["pcr11"], "bb".repeat(32));
    }

    /// The deploy report documents what was checked: the network identity the
    /// binding committed to and the nonce that made the quote fresh.
    #[test]
    fn report_extras_document_the_deploy_check() {
        let network_id = NetworkId::from_bytes([0x11; 32]);
        let deployment_nonce = [0x66u8; 32];
        let verified = VerifiedDeploy {
            report: QuoteReport {
                binding: deploy_binding(&network_id, &deployment_nonce),
                pcrs: BTreeMap::from([(4, [0x44; 32])]),
            },
            network_id,
            deployment_nonce,
        };

        let report = verified.to_json();

        assert_eq!(report["verified"], true);
        assert_eq!(report["network_id"], format!("0x{}", "11".repeat(32)));
        assert_eq!(report["deployment_nonce"], "66".repeat(32));
    }

    /// A file that isn't a manifest is named as such, rather than hashing to
    /// some id and surfacing later as a binding mismatch — which reads as a
    /// node that answered for another network. The parse comes before the
    /// node is contacted, so the endpoint here is never reached.
    #[tokio::test]
    async fn deploy_rejects_a_manifest_that_is_not_one() {
        let error = verify_deploy(
            "http://127.0.0.1:1",
            b"{}".as_slice(),
            policy(VALID_POLICY),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("not a v1 network manifest"), "{error}");
    }

    #[tokio::test]
    async fn deploy_malformed_endpoint_is_rejected() {
        let manifest =
            include_str!("../../../crates/network-manifest/fixtures/network-manifest-v1.json");
        let error = verify_deploy("not a url", manifest.as_bytes(), policy(VALID_POLICY), None)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a usable URL"), "{error}");
    }
}
