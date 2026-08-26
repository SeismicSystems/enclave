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
//!   --policy build/measurements.json
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
//! Verification-only: this never touches a local TPM. Azure TDX verification
//! is pure computation over the evidence bytes (the `azure-verifier` feature
//! of the `attestation` backend), so it builds and runs anywhere, including
//! macOS; `deploy` additionally makes one JSON-RPC request to the target node.

use anyhow::Context as _;
use clap::{Args, Parser, Subcommand};
use jsonrpsee::http_client::HttpClientBuilder;
use seismic_attestation::{
    AttestationExchangeMessage, AttestationType, NetworkId, NetworkManifestV1,
    SeismicMeasurementPolicy, VerifiedAzureAttestation, VerifiedSeismicAttestation, VerifyOptions,
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

    /// Allow the backend's Azure outdated-TCB override path.
    #[arg(long)]
    override_azure_outdated_tcb: bool,
}

#[derive(Debug, Args)]
struct HarvestCli {
    /// The node's harvest record, e.g. a founding archive's
    /// `inputs/harvest/<node>.json` (`-` reads stdin).
    #[arg(long, value_name = "PATH")]
    record: PathBuf,

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
    let verified = verify_azure(record.evidence, binding, policy, &cli.common)
        .await
        .context("verifying harvest evidence")?;
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
    let verified = verify_azure(response.evidence, binding, policy, &cli.common)
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

/// Verify Azure TDX evidence against `binding` and `policy`.
///
/// Wrong-platform evidence is rejected on the claimed type, before
/// verification: DCAP verification costs collateral round-trips, and this
/// policy format cannot pin a non-Azure platform's measurements anyway.
async fn verify_azure(
    evidence: AttestationExchangeMessage,
    binding: [u8; 64],
    policy: SeismicMeasurementPolicy,
    common: &CommonArgs,
) -> anyhow::Result<VerifiedAzureAttestation> {
    anyhow::ensure!(
        evidence.attestation_type() == AttestationType::AzureTdx,
        "expected {} evidence, got {}",
        AttestationType::AzureTdx.as_str(),
        evidence.attestation_type().as_str(),
    );

    let verified = verify_evidence_with_policy(
        evidence,
        binding,
        policy,
        VerifyOptions {
            pccs_url: common.pccs_url.clone(),
            dump_dcap_quotes: false,
            override_azure_outdated_tcb: common.override_azure_outdated_tcb,
        },
    )
    .await?;
    let VerifiedSeismicAttestation::AzureTdx(verified) = verified else {
        anyhow::bail!("verified output is not azure-tdx despite azure-tdx evidence: {verified:?}");
    };
    Ok(verified)
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

    const NONCE_HEX: &str = "7777777777777777777777777777777777777777777777777777777777777777";
    const NODE_PK_HEX: &str = "8888888888888888888888888888888888888888888888888888888888888888";
    const CONSENSUS_PK_HEX: &str = "999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999";

    fn write_file(dir: &tempfile::TempDir, name: &str, contents: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).expect("writing test input");
        path
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
