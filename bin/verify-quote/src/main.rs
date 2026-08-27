//! `verify-quote` — operator-side relying party for Seismic node quotes.
//!
//! Two checks, one per subcommand, sharing one DCAP verification path
//! (`seismic-attestation` over the complete evidence envelope, enforcing the
//! measurement policy). The subcommands differ only in which binding they
//! recompute and where the evidence comes from:
//!
//! - `harvest` checks one founding node's summit-keys harvest quote, taking
//!   that node's whole harvest record (see [`HarvestRecord`]): the record's
//!   evidence must carry
//!   `founding_summit_keys_binding(harvest_nonce, node_public_key,
//!   consensus_public_key)` over the record's own claims. The record is per
//!   node, so one run covers one node's harvest.
//! - `deploy` checks a freshly provisioned node before the operator relies
//!   on it (publishing its address, handing it out as a bootnode): it mints a
//!   fresh `deployment_nonce`, requests evidence from the node's attestation
//!   service (`getDeployVerificationEvidence` at `--endpoint`), and
//!   recomputes `deploy_verification_binding(network_id, nonce)` from its own
//!   copy of the network manifest.
//!
//! ```text
//! verify-quote harvest \
//!   --record inputs/harvest/box-1.json \
//!   --policy build/measurements.json \
//!   --dump-collateral /tmp/box-1-collateral.json
//!
//! verify-quote harvest \
//!   --record inputs/harvest/box-1.json \
//!   --policy build/measurements.json \
//!   --collateral inputs/harvest/dcap-collateral/box-1.json
//!
//! verify-quote deploy \
//!   --endpoint http://<node-ip>:7878 \
//!   --manifest network-manifest.json \
//!   --policy build/measurements.json
//! ```
//!
//! `--record` is a harvest-record JSON document; `-` reads it from stdin. Exit 0
//! plus one JSON object on stdout means verified. Every failure — bad input,
//! binding mismatch, measurement mismatch, DCAP failure, non-Azure evidence —
//! is an error on stderr with a nonzero exit and nothing on stdout.
//!
//! `--dump-collateral` writes the Intel collateral a harvest verified
//! against to its own file, once the quote has verified. The destination is
//! the caller's scratch space: a founding archive admits a cohort's
//! collateral all at once, so the file is theirs to move into place once
//! every box has passed.
//!
//! `--collateral` is the other end of that archive, and the mode an auditor
//! runs: the record is verified against the snapshot beside it, at the
//! instant that snapshot was held to, reaching no collateral service at all.
//! The snapshot names the record it belongs to by `harvest_nonce`, so a
//! snapshot filed beside the wrong record is refused rather than replayed.
//! Intel's TCB Info, QE Identity and both CRLs carry `nextUpdate` on a
//! roughly 30-day cadence, so this is the only mode under which a founding
//! quote still verifies a month after the founding.
//!
//! Verification-only: this never touches a local TPM. Azure TDX verification
//! is pure computation over the evidence bytes (the `azure-verifier` feature
//! of the `attestation` backend), so it builds and runs anywhere, including
//! macOS; `deploy` additionally makes one JSON-RPC request to the target node.

mod collateral;

use anyhow::Context as _;
use clap::{Args, Parser, Subcommand};
use jsonrpsee::http_client::HttpClientBuilder;
use seismic_attestation::{
    AttestationExchangeMessage, AttestationType, CollateralSnapshot, NetworkId, NetworkManifestV1,
    SeismicMeasurementPolicy, VerifiedAzureAttestation, VerifiedEvidence,
    VerifiedSeismicAttestation, VerifyMode, VerifyOptions,
    bindings::{
        binding64_from_digest32, deploy_verification_binding, founding_summit_keys_binding,
    },
    verify_evidence_with_policy,
};
use seismic_attestation_rpc::AttestationRpcClient as _;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    io::Read as _,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Parser)]
#[command(
    name = "verify-quote",
    version,
    about = "Verify Seismic node quotes against the intended image measurements",
    long_about = "Verify Seismic node quotes against the intended image measurements.\n\n\
                  Each subcommand recomputes its purpose-specific binding, verifies the \
                  evidence cryptographically, and enforces --policy on the quoted \
                  measurements. The policy is required: there is no accept-any mode, because \
                  the measurement check is the point.\n\n\
                  Exit 0 with a single JSON object on stdout means verified. Any failure — \
                  unreadable or malformed input, binding mismatch, measurement mismatch, DCAP \
                  failure, non-Azure evidence — prints an error to stderr and exits nonzero, \
                  with nothing on stdout.\n\n\
                  Verification-only: this never touches a local TPM, and Azure TDX \
                  verification is pure computation over the evidence bytes, so it builds and \
                  runs anywhere, including macOS."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// DCAP-verify one founding node's summit-keys harvest quote
    #[command(
        long_about = "DCAP-verify one founding node's summit-keys harvest quote, given that \
                      node's harvest record from the founding archive.\n\n\
                      Recomputes the report_data the key holder must have quoted over \
                      (founding_summit_keys_binding of the record's harvest_nonce, \
                      node_public_key and consensus_public_key) and verifies the record's \
                      evidence against it.\n\n\
                      The success report's pcrs map carries every register the quote covers, \
                      not just the ones the policy pins, so the caller can archive it as \
                      harvest provenance."
    )]
    Harvest(HarvestCli),

    /// DCAP-verify a freshly provisioned node before relying on it
    #[command(
        long_about = "DCAP-verify a freshly provisioned node before relying on it — \
                      publishing its address, handing it to later nodes as a bootnode, \
                      pointing tooling at it.\n\n\
                      Mints a fresh deployment_nonce, requests evidence from the node's \
                      attestation service (getDeployVerificationEvidence at --endpoint), \
                      recomputes deploy_verification_binding from --manifest's network \
                      identity and the nonce, and verifies the returned envelope. A pass \
                      proves a measured node holding this manifest answered this exact \
                      request.\n\n\
                      The check protects only the operator's own decisions: membership in \
                      the network is granted by the network's own gates (the attested \
                      root-key handshake and its admission policy), never by this check."
    )]
    Deploy(DeployCli),
}

/// Flags shared by every verification purpose.
#[derive(Debug, Args)]
struct CommonArgs {
    /// Measurement-policy JSON pinning the intended image measurements, e.g.
    /// seismic-images' `build/measurements.json`. Required: a quote from an
    /// unintended image must not pass.
    #[arg(long, value_name = "PATH")]
    policy: PathBuf,

    /// Optional PCCS URL for DCAP collateral, instead of the backend default.
    #[arg(long, value_name = "URL")]
    pccs_url: Option<String>,
}

#[derive(Debug, Args)]
struct HarvestCli {
    /// The node's harvest record, e.g. a founding archive's
    /// `inputs/harvest/<node>.json` (`-` reads stdin).
    #[arg(long, value_name = "PATH")]
    record: PathBuf,

    /// Write the DCAP collateral this verification consumed to PATH, once
    /// the quote has verified. Somewhere disposable: the caller archives it.
    #[arg(long, value_name = "PATH")]
    dump_collateral: Option<PathBuf>,

    /// Verify against the archived collateral snapshot at PATH, at the
    /// instant it was held to, instead of fetching and using the wall clock.
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["dump_collateral", "pccs_url"]
    )]
    collateral: Option<PathBuf>,

    #[command(flatten)]
    common: CommonArgs,
}

/// One founding node's harvest record: the four facts a harvest quote is
/// verified against, in one JSON document.
///
/// This is the founding harvest archive's schema, and what makes the archive
/// re-verifiable: deploy writes one such document per node when it collects
/// the keys, and anyone re-checking the founding set later hands the same file
/// straight back to `harvest`. What the archive keeps alongside these fields
/// (when the harvest ran, the report of the verification that passed) is
/// ignored here, so an archived file verifies as-is.
///
/// The three claims are untrusted input: the quote's `report_data` is what
/// decides whether the node's keys really are these, so a wrong claim surfaces
/// as a binding mismatch.
#[derive(Debug, Deserialize)]
struct HarvestRecord {
    /// The nonce the quote was requested with (32 bytes hex).
    harvest_nonce: String,

    /// The ed25519 node pubkey the key holder served (32 bytes hex).
    node_public_key: String,

    /// The BLS12-381 MinPk consensus pubkey the key holder served
    /// (48 bytes hex).
    consensus_public_key: String,

    /// The evidence the key holder served, verbatim.
    evidence: AttestationExchangeMessage,
}

#[derive(Debug, Args)]
struct DeployCli {
    /// The node's attestation-service JSON-RPC endpoint,
    /// e.g. http://<node-ip>:7878.
    #[arg(long, value_name = "URL")]
    endpoint: String,

    /// The network-manifest.json the node is expected to have booted with.
    /// Its exact bytes are the network identity the binding commits to.
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,

    #[command(flatten)]
    common: CommonArgs,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Returning the error from main sends it to stderr with a nonzero exit and
    // leaves stdout empty, which is exactly the deploy tooling's contract.
    println!("{}", run(Cli::parse()).await?);
    Ok(())
}

/// Verify the quote described by `cli` and render the success report.
///
/// Separate from `main` so the whole path — including every rejection — is
/// callable from tests.
async fn run(cli: Cli) -> anyhow::Result<String> {
    match cli.command {
        Command::Harvest(harvest) => run_harvest(harvest).await,
        Command::Deploy(deploy) => run_deploy(deploy).await,
    }
}

async fn run_harvest(cli: HarvestCli) -> anyhow::Result<String> {
    // Resolve everything that can fail on bad input before any verification:
    // DCAP costs collateral round-trips, so a malformed record should not be
    // discovered on the far side of them.
    let record_bytes = read_record(&cli.record).await?;
    let record: HarvestRecord =
        serde_json::from_slice(&record_bytes).context("--record is not a harvest record")?;
    let nonce = decode_hex_field::<32>("harvest_nonce", &record.harvest_nonce)?;
    let node_pk = decode_hex_field::<32>("node_public_key", &record.node_public_key)?;
    let consensus_pk =
        decode_hex_field::<48>("consensus_public_key", &record.consensus_public_key)?;
    let binding = harvest_binding(&nonce, &node_pk, &consensus_pk);

    let policy = load_policy(&cli.common.policy).await?;
    let mode = match &cli.collateral {
        Some(path) => archived_mode(path, &nonce).await?,
        None => VerifyMode::Live,
    };
    let (verified, collateral) = verify_azure(record.evidence, binding, policy, mode, &cli.common)
        .await
        .context("verifying harvest evidence")?;
    // After the verdict, never before: a burned harvest must not leave a
    // half-archive behind for a later reader to trust.
    if let Some(path) = &cli.dump_collateral {
        dump_collateral(path, &nonce, &collateral).await?;
    }
    Ok(report(&verified, []))
}

async fn run_deploy(cli: DeployCli) -> anyhow::Result<String> {
    // Resolve every local input before contacting the node: a mistyped path
    // should not be discovered on the far side of an RPC round-trip.
    let manifest_bytes = tokio::fs::read(&cli.manifest)
        .await
        .with_context(|| format!("reading --manifest {}", cli.manifest.display()))?;
    // Parse strictly, then derive the id from the same raw bytes. The parse is
    // what separates "you passed the wrong file" from "this node answered for
    // another network": without it, any file hashes to some id and the run
    // fails as a binding mismatch — the alarm that makes an operator burn a box.
    NetworkManifestV1::from_json_bytes(&manifest_bytes).with_context(|| {
        format!(
            "--manifest {} is not a v1 network manifest",
            cli.manifest.display()
        )
    })?;
    let network_id = NetworkId::from_manifest_bytes(&manifest_bytes);
    let policy = load_policy(&cli.common.policy).await?;
    let client = HttpClientBuilder::default()
        // Quote generation opens the node's TPM exclusively and is serialized
        // in-process, so a busy node answers in seconds, not milliseconds.
        .request_timeout(Duration::from_secs(120))
        .build(&cli.endpoint)
        .with_context(|| format!("--endpoint {} is not a usable URL", cli.endpoint))?;

    // Minted here and never handed to anyone but the node under test, so the
    // returned quote can only answer this exact request.
    let deployment_nonce: [u8; 32] = rand::random();
    let response = client
        .get_deploy_verification_evidence(deployment_nonce)
        .await
        .with_context(|| {
            format!(
                "requesting deploy-verification evidence from --endpoint {}",
                cli.endpoint
            )
        })?;

    let binding = deploy_binding(&network_id, &deployment_nonce);
    // The collateral goes unarchived here: a live challenge is fresh
    // evidence, judged against fresh collateral at the wall clock.
    let (verified, _collateral) = verify_azure(
        response.evidence,
        binding,
        policy,
        VerifyMode::Live,
        &cli.common,
    )
    .await
    .context("verifying deploy-verification evidence")?;
    // The extras document what was checked: which network identity the binding
    // committed to, and the nonce that made this run's quote fresh.
    Ok(report(
        &verified,
        [
            ("network_id", network_id.to_string()),
            ("deployment_nonce", hex::encode(deployment_nonce)),
        ],
    ))
}

/// The 64-byte `report_data` a harvested quote must carry.
///
/// Pure and deliberately trivial: the deploy tooling calls this binary
/// instead of deriving the binding itself, so this one line is the single
/// definition of the check on both sides.
fn harvest_binding(nonce: &[u8; 32], node_pk: &[u8; 32], consensus_pk: &[u8; 48]) -> [u8; 64] {
    binding64_from_digest32(founding_summit_keys_binding(nonce, node_pk, consensus_pk))
}

/// The 64-byte `report_data` a deploy-verification quote must carry
/// (same single-definition rationale as [`harvest_binding`]).
fn deploy_binding(network_id: &NetworkId, deployment_nonce: &[u8; 32]) -> [u8; 64] {
    binding64_from_digest32(deploy_verification_binding(network_id, deployment_nonce))
}

/// Load the measurement policy, failing closed: this binary has no accept-any
/// path, so an unparseable policy must stop the run rather than widen it.
async fn load_policy(path: &Path) -> anyhow::Result<SeismicMeasurementPolicy> {
    SeismicMeasurementPolicy::from_file(path.to_path_buf())
        .await
        .with_context(|| format!("loading measurement policy {}", path.display()))
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
    common: &CommonArgs,
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
            pccs_url: common.pccs_url.clone(),
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

/// Resolve `--collateral` into the mode it names, for the record whose
/// `harvest_nonce` is `nonce`.
///
/// The archived snapshot is the whole input: the bundle Intel served, and the
/// instant the founding verification held it to be current. So this reaches
/// no collateral service, and `--pccs-url` has nothing left to reach.
///
/// The snapshot has to be the one this record's verification produced. The
/// instant decides which validity and revocation windows are open, so a
/// snapshot filed beside another box's record would evaluate the quote at
/// the wrong instant against the wrong bundle. Neither file is signed, so
/// this is not a trust boundary; it catches the mispairing an archive comes
/// to by accident, exactly, since no two records share a nonce.
async fn archived_mode(path: &Path, nonce: &[u8; 32]) -> anyhow::Result<VerifyMode> {
    let document = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("reading --collateral {}", path.display()))?;
    let archived = collateral::parse(&document).with_context(|| {
        format!(
            "--collateral {} is not an archived snapshot",
            path.display()
        )
    })?;
    anyhow::ensure!(
        &archived.harvest_nonce == nonce,
        "--collateral {} belongs to the record with harvest_nonce {}, not to this one ({}): \
         they are not from one harvest",
        path.display(),
        hex::encode(archived.harvest_nonce),
        hex::encode(nonce),
    );
    Ok(VerifyMode::Archived(archived.snapshot))
}

/// Archive the DCAP collateral the verification of the record with
/// `harvest_nonce` `nonce` consumed.
///
/// The caller owns the layout and passes the destination; this writes the
/// exact bundle the verdict depended on, so what is archived is what was
/// verified.
async fn dump_collateral(
    path: &Path,
    nonce: &[u8; 32],
    collateral: &CollateralSnapshot,
) -> anyhow::Result<()> {
    let archived = collateral::ArchivedSnapshot {
        harvest_nonce: *nonce,
        snapshot: collateral.clone(),
    };
    let document = collateral::render(&archived)?;
    // Read the document back before it leaves this process. The caller
    // archives these bytes verbatim and nothing parses them again until a
    // re-verification that may be a year away, so a snapshot that does not
    // round-trip has to fail the harvest that produced it.
    let reread = collateral::parse(&document).context("re-reading the rendered DCAP collateral")?;
    anyhow::ensure!(
        reread == archived,
        "the rendered DCAP collateral does not read back as the collateral this verification used"
    );
    tokio::fs::write(path, document)
        .await
        .with_context(|| format!("writing --dump-collateral {}", path.display()))
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

/// Read the harvest record from a path, or stdin for `-` (the subprocess
/// boundary deploy uses to pass exact bytes without a temp file).
async fn read_record(path: &Path) -> anyhow::Result<Vec<u8>> {
    if path == Path::new("-") {
        let mut bytes = Vec::new();
        std::io::stdin()
            .read_to_end(&mut bytes)
            .context("reading --record from stdin")?;
        return Ok(bytes);
    }
    tokio::fs::read(path)
        .await
        .with_context(|| format!("reading --record {}", path.display()))
}

/// The success report: one JSON object, printed only once verification passed.
///
/// Registers come out of a `BTreeMap` so the object is assembled in register
/// order and archived reports diff cleanly across nodes, boots, and builds (the
/// backend hands back a `HashMap`, whose iteration order is not stable). Every
/// quoted register is included, not just the policy's, because the caller keeps
/// this output as provenance. `extras` carries the purpose-specific facts of
/// what was checked.
fn report(
    verified: &VerifiedAzureAttestation,
    extras: impl IntoIterator<Item = (&'static str, String)>,
) -> String {
    let pcrs: serde_json::Map<String, serde_json::Value> = verified
        .guest_measurements
        .pcrs
        .iter()
        .map(|(index, value)| (*index, *value))
        .collect::<BTreeMap<u32, [u8; 32]>>()
        .into_iter()
        .map(|(index, value)| (format!("pcr{index}"), hex::encode(value).into()))
        .collect();

    let mut object = serde_json::json!({
        "verified": true,
        "attestation_type": AttestationType::AzureTdx.as_str(),
        "binding": hex::encode(verified.binding),
        "pcrs": pcrs,
    });
    for (key, value) in extras {
        object
            .as_object_mut()
            .expect("report literal is an object")
            .insert(key.to_string(), value.into());
    }
    object.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;
    use seismic_attestation::AzureGuestMeasurements;
    use std::collections::HashMap;

    /// A policy that parses. Its measurements never get checked in these tests:
    /// every case here fails before verification, which is the point — no test
    /// in this file reaches live DCAP.
    const VALID_POLICY: &str = r#"[
      {
        "attestation_type": "azure-tdx",
        "measurement_id": "verify-quote-test.vhd",
        "measurements": {
          "pcr4": { "expected_any": ["d57063c0669599b885c43a0683436a3463ad49513ddb3996e6fc96040508fd8e"] }
        }
      }
    ]"#;

    /// The manifest fixture the whole repo shares, so `deploy`'s strict parse
    /// is exercised against the same document the node parses at boot.
    const VALID_MANIFEST: &str =
        include_str!("../../../crates/network-manifest/fixtures/network-manifest-v1.json");

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

    fn write_file(dir: &tempfile::TempDir, name: &str, contents: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).expect("writing test input");
        path
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

    fn harvest_cli(record: &Path, policy: &Path) -> Cli {
        Cli::try_parse_from([
            "verify-quote".as_ref(),
            "harvest".as_ref(),
            "--record".as_ref(),
            record.as_os_str(),
            "--policy".as_ref(),
            policy.as_os_str(),
        ])
        .expect("well-formed argv")
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

    fn deploy_cli(endpoint: &str, manifest: &Path, policy: &Path) -> Cli {
        Cli::try_parse_from([
            "verify-quote".as_ref(),
            "deploy".as_ref(),
            "--endpoint".as_ref(),
            endpoint.as_ref(),
            "--manifest".as_ref(),
            manifest.as_os_str(),
            "--policy".as_ref(),
            policy.as_os_str(),
        ])
        .expect("well-formed argv")
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    /// Capturing the collateral is optional, and its destination is the
    /// caller's: deploy owns the founding archive's layout, so the path
    /// arrives on argv. `deploy` has no such flag — a live challenge is
    /// judged against live collateral and archives nothing.
    #[test]
    fn dump_collateral_is_optional_and_harvest_only() {
        let dir = tempfile::tempdir().unwrap();
        let record = write_file(&dir, "node-1.json", &record_json("{}"));
        let policy = write_file(&dir, "policy.json", VALID_POLICY);

        let Command::Harvest(harvest) = harvest_cli(&record, &policy).command else {
            panic!("expected the harvest subcommand");
        };
        assert_eq!(harvest.dump_collateral, None);

        let destination = dir.path().join("dcap-collateral/node-1.json");
        let cli = Cli::try_parse_from([
            "verify-quote".as_ref(),
            "harvest".as_ref(),
            "--record".as_ref(),
            record.as_os_str(),
            "--policy".as_ref(),
            policy.as_os_str(),
            "--dump-collateral".as_ref(),
            destination.as_os_str(),
        ])
        .expect("well-formed argv");
        let Command::Harvest(harvest) = cli.command else {
            panic!("expected the harvest subcommand");
        };
        assert_eq!(
            harvest.dump_collateral.as_deref(),
            Some(destination.as_path())
        );

        assert!(
            Cli::try_parse_from([
                "verify-quote".as_ref(),
                "deploy".as_ref(),
                "--endpoint".as_ref(),
                "http://127.0.0.1:1".as_ref(),
                "--manifest".as_ref(),
                policy.as_os_str(),
                "--policy".as_ref(),
                policy.as_os_str(),
                "--dump-collateral".as_ref(),
                destination.as_os_str(),
            ])
            .is_err()
        );
    }

    /// A harvest CLI in offline mode over the given collateral document.
    fn offline_cli(dir: &tempfile::TempDir, record: &str, document: &str) -> Cli {
        let record = write_file(dir, "node-1.json", record);
        let policy = write_file(dir, "policy.json", VALID_POLICY);
        let snapshot = write_file(dir, "node-1-collateral.json", document);
        Cli::try_parse_from([
            "verify-quote".as_ref(),
            "harvest".as_ref(),
            "--record".as_ref(),
            record.as_os_str(),
            "--policy".as_ref(),
            policy.as_os_str(),
            "--collateral".as_ref(),
            snapshot.as_os_str(),
        ])
        .expect("well-formed argv")
    }

    const NO_ATTESTATION: &str = r#"{ "attestation_type": "none", "attestation": [] }"#;

    /// `--collateral` is the whole collateral input: capture verifies live
    /// and writes, replay reads and verifies offline, and an offline run
    /// reaches no collateral service. So it excludes both the flag that
    /// captures and the flag that points at a PCCS — each would name
    /// something the run does not do.
    #[test]
    fn offline_mode_excludes_capture_and_the_pccs() {
        let dir = tempfile::tempdir().unwrap();
        let record = write_file(&dir, "node-1.json", &record_json("{}"));
        let policy = write_file(&dir, "policy.json", VALID_POLICY);
        let snapshot = dir.path().join("node-1-collateral.json");

        for extra in [
            vec!["--dump-collateral", snapshot.to_str().unwrap()],
            vec!["--pccs-url", "http://127.0.0.1:8081"],
        ] {
            let mut argv = vec![
                "verify-quote",
                "harvest",
                "--record",
                record.to_str().unwrap(),
                "--policy",
                policy.to_str().unwrap(),
                "--collateral",
                snapshot.to_str().unwrap(),
            ];
            argv.extend(extra.iter().copied());
            assert!(Cli::try_parse_from(&argv).is_err(), "{argv:?}");
        }
    }

    /// The instant decides which validity and revocation windows are open, so
    /// a snapshot has to be the one this record's verification produced. The
    /// snapshot names its record by nonce, and no two records share one, so
    /// a snapshot filed beside another box's record is refused exactly.
    #[tokio::test]
    async fn replay_pairs_a_snapshot_with_its_record_by_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let document = collateral::render(&collateral::fabricated_snapshot()).unwrap();
        let path = write_file(&dir, "node-1-collateral.json", &document);

        let mode = archived_mode(&path, &collateral::FABRICATED_NONCE)
            .await
            .unwrap();
        assert_eq!(
            mode,
            VerifyMode::Archived(collateral::fabricated_collateral())
        );

        let other_record = [0xa5u8; 32];
        let error = archived_mode(&path, &other_record)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("not from one harvest"), "{error}");
        assert!(error.contains(&hex::encode(other_record)), "{error}");
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
        let dir = tempfile::tempdir().unwrap();
        let record = write_file(&dir, "founding-record.json", FOUNDING_RECORD);
        let policy = write_file(&dir, "founding-policy.json", FOUNDING_POLICY);
        let snapshot = write_file(&dir, "founding-collateral.json", FOUNDING_COLLATERAL);

        // Asserted before verifying: a fixture re-captured without its
        // instant should fail here, not as a puzzling expiry years from now.
        let archived = collateral::parse(FOUNDING_COLLATERAL).expect("archived snapshot");
        assert_eq!(archived.snapshot.at, FOUNDING_VERIFIED_AT);

        let rendered = run(Cli::try_parse_from([
            "verify-quote".as_ref(),
            "harvest".as_ref(),
            "--record".as_ref(),
            record.as_os_str(),
            "--policy".as_ref(),
            policy.as_os_str(),
            "--collateral".as_ref(),
            snapshot.as_os_str(),
        ])
        .expect("well-formed argv"))
        .await
        .expect("the archived founding verifies offline");

        let report: serde_json::Value = serde_json::from_str(&rendered).unwrap();
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
        let dir = tempfile::tempdir().unwrap();
        let record = write_file(&dir, "founding-record.json", FOUNDING_RECORD);
        let policy = write_file(&dir, "founding-policy.json", FOUNDING_POLICY);

        // 2027-01-15, months past every window in the archived bundle. Only
        // the instant changes; the collateral is the same bytes that verify
        // in the test above.
        let mut document: serde_json::Value = serde_json::from_str(FOUNDING_COLLATERAL).unwrap();
        document["verified_at"] = serde_json::json!(1_800_000_000u64);
        let snapshot = write_file(&dir, "founding-collateral.json", &document.to_string());

        let error = run(Cli::try_parse_from([
            "verify-quote".as_ref(),
            "harvest".as_ref(),
            "--record".as_ref(),
            record.as_os_str(),
            "--policy".as_ref(),
            policy.as_os_str(),
            "--collateral".as_ref(),
            snapshot.as_os_str(),
        ])
        .expect("well-formed argv"))
        .await
        .expect_err("an expired bundle must not verify");
        assert!(
            format!("{error:#}").contains("DCAP"),
            "expected a DCAP freshness failure, got: {error:#}"
        );
    }

    /// The dump names the record it was verified with, so the snapshot a
    /// harvest archives is the one its own replay accepts.
    #[tokio::test]
    async fn dump_names_the_record_it_verified() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node-1-collateral.json");
        let nonce = [0x3cu8; 32];

        dump_collateral(&path, &nonce, &collateral::fabricated_collateral())
            .await
            .unwrap();
        let archived = collateral::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(archived.harvest_nonce, nonce);
        assert_eq!(archived.snapshot, collateral::fabricated_collateral());
    }

    /// Offline mode fails by flag name on every way the snapshot can be
    /// unusable, since a reader who mistypes the path must not be told the
    /// founding failed to verify.
    #[tokio::test]
    async fn offline_mode_fails_by_flag_name_on_an_unusable_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let record = record_json(NO_ATTESTATION);

        for document in ["not json at all", r#"{ "version": 2 }"#] {
            let error = run(offline_cli(&dir, &record, document))
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains("--collateral"), "{error}");
        }

        let policy = write_file(&dir, "policy.json", VALID_POLICY);
        let record_path = write_file(&dir, "record.json", &record);
        let missing = dir.path().join("absent.json");
        let error = run(Cli::try_parse_from([
            "verify-quote".as_ref(),
            "harvest".as_ref(),
            "--record".as_ref(),
            record_path.as_os_str(),
            "--policy".as_ref(),
            policy.as_os_str(),
            "--collateral".as_ref(),
            missing.as_os_str(),
        ])
        .expect("well-formed argv"))
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("--collateral"), "{error}");
    }

    /// The dump follows the verdict: a run that does not verify leaves no
    /// collateral behind, so a burned harvest cannot leave a half-archive a
    /// later reader mistakes for provenance.
    #[tokio::test]
    async fn a_failed_verification_writes_no_collateral() {
        let dir = tempfile::tempdir().unwrap();
        let record = write_file(
            &dir,
            "node-1.json",
            &record_json(r#"{ "attestation_type": "none", "attestation": [] }"#),
        );
        let policy = write_file(&dir, "policy.json", VALID_POLICY);
        let destination = dir.path().join("node-1-collateral.json");

        let cli = Cli::try_parse_from([
            "verify-quote".as_ref(),
            "harvest".as_ref(),
            "--record".as_ref(),
            record.as_os_str(),
            "--policy".as_ref(),
            policy.as_os_str(),
            "--dump-collateral".as_ref(),
            destination.as_os_str(),
        ])
        .expect("well-formed argv");

        assert!(run(cli).await.is_err());
        assert!(!destination.exists());
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
        let record: HarvestRecord = serde_json::from_str(&archived).expect("archived record");

        assert_eq!(
            decode_hex_field::<32>("harvest_nonce", &record.harvest_nonce).unwrap(),
            [0x77; 32]
        );
        assert_eq!(
            decode_hex_field::<48>("consensus_public_key", &record.consensus_public_key).unwrap(),
            [0x99; 48]
        );
    }

    #[tokio::test]
    async fn malformed_record_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let record = write_file(&dir, "node-1.json", "{ not a record");
        let policy = write_file(&dir, "policy.json", VALID_POLICY);

        let error = run(harvest_cli(&record, &policy))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("--record"), "{error}");
    }

    /// A record whose evidence field is not an evidence envelope fails as a bad
    /// record, before any collateral is fetched.
    #[tokio::test]
    async fn record_with_malformed_evidence_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let record = write_file(&dir, "node-1.json", &record_json(r#""not an envelope""#));
        let policy = write_file(&dir, "policy.json", VALID_POLICY);

        let error = run(harvest_cli(&record, &policy))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("--record"), "{error}");
    }

    #[tokio::test]
    async fn missing_record_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let policy = write_file(&dir, "policy.json", VALID_POLICY);

        let error = run(harvest_cli(&dir.path().join("absent.json"), &policy))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("reading --record"), "{error}");
    }

    /// Fail-closed on the policy: this binary has no accept-any path, so an
    /// unparseable policy must stop the run rather than widen it.
    #[tokio::test]
    async fn malformed_policy_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let record = write_file(
            &dir,
            "node-1.json",
            &record_json(r#"{ "attestation_type": "azure-tdx", "attestation": [1, 2, 3] }"#),
        );
        let policy = write_file(&dir, "policy.json", "{ not a policy");

        let error = run(harvest_cli(&record, &policy))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("measurement policy"), "{error}");
    }

    /// One job, one binding: a quote from a platform whose measurements this
    /// policy format cannot pin is rejected without any collateral fetching.
    #[tokio::test]
    async fn non_azure_evidence_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let record = write_file(
            &dir,
            "node-1.json",
            &record_json(r#"{ "attestation_type": "none", "attestation": [] }"#),
        );
        let policy = write_file(&dir, "policy.json", VALID_POLICY);

        assert!(run(harvest_cli(&record, &policy)).await.is_err());
    }

    #[tokio::test]
    async fn deploy_missing_manifest_fails_by_flag_name() {
        let dir = tempfile::tempdir().unwrap();
        let policy = write_file(&dir, "policy.json", VALID_POLICY);

        let error = run(deploy_cli(
            "http://127.0.0.1:1",
            &dir.path().join("absent.json"),
            &policy,
        ))
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("reading --manifest"), "{error}");
    }

    /// A file that isn't a manifest is named as such, rather than hashing to
    /// some id and surfacing later as a binding mismatch — which reads as a
    /// node that answered for another network.
    #[tokio::test]
    async fn deploy_rejects_a_manifest_that_is_not_one() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write_file(&dir, "reth-genesis.json", "{}");
        let policy = write_file(&dir, "policy.json", VALID_POLICY);

        let error = run(deploy_cli("http://127.0.0.1:1", &manifest, &policy))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a v1 network manifest"), "{error}");
    }

    /// Local inputs resolve before the node is contacted: a bad policy fails
    /// even though the endpoint points nowhere, proving no RPC was attempted.
    #[tokio::test]
    async fn deploy_resolves_local_inputs_before_contacting_the_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write_file(&dir, "network-manifest.json", VALID_MANIFEST);
        let policy = write_file(&dir, "policy.json", "{ not a policy");

        let error = run(deploy_cli("http://127.0.0.1:1", &manifest, &policy))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("measurement policy"), "{error}");
    }

    #[tokio::test]
    async fn deploy_malformed_endpoint_fails_by_flag_name() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write_file(&dir, "network-manifest.json", VALID_MANIFEST);
        let policy = write_file(&dir, "policy.json", VALID_POLICY);

        let error = run(deploy_cli("not a url", &manifest, &policy))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("--endpoint"), "{error}");
    }

    #[test]
    fn report_carries_every_quoted_register() {
        let verified = VerifiedAzureAttestation {
            binding: harvest_binding(&[0x77; 32], &[0x88; 32], &[0x99; 48]),
            guest_measurements: AzureGuestMeasurements {
                pcrs: HashMap::from([(11, [0xbb; 32]), (4, [0x44; 32]), (9, [0x99; 32])]),
            },
        };

        let report: serde_json::Value = serde_json::from_str(&report(&verified, [])).unwrap();

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
        let nonce = [0x66u8; 32];
        let verified = VerifiedAzureAttestation {
            binding: deploy_binding(&network_id, &nonce),
            guest_measurements: AzureGuestMeasurements {
                pcrs: HashMap::from([(4, [0x44; 32])]),
            },
        };

        let rendered = report(
            &verified,
            [
                ("network_id", network_id.to_string()),
                ("deployment_nonce", hex::encode(nonce)),
            ],
        );
        let report: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(report["verified"], true);
        assert_eq!(report["network_id"], format!("0x{}", "11".repeat(32)));
        assert_eq!(report["deployment_nonce"], "66".repeat(32));
    }
}
