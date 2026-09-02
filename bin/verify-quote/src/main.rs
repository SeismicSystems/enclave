//! `verify-quote` — operator-side relying party for Seismic node quotes.
//!
//! Clap over the crate's library, which holds the verification itself: two
//! checks, one per subcommand, sharing one DCAP verification path.
//!
//! - `harvest` checks one founding node's summit-keys harvest quote, taking
//!   that node's whole harvest record from the founding archive.
//! - `deploy` checks a freshly provisioned node before the operator relies on
//!   it, by challenging its attestation service with a fresh nonce.
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
//!
//! This binary exists for the subprocess boundary. Rust callers link the
//! library instead.

use anyhow::Context as _;
use clap::{Args, Parser, Subcommand};
use seismic_verify_quote::{
    ArchivedSnapshot, HarvestCollateral, HarvestRecord, SeismicMeasurementPolicy, collateral,
    verify_deploy, verify_harvest,
};
use std::{
    io::Read as _,
    path::{Path, PathBuf},
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
    // Resolve everything the filesystem can fail on before any verification:
    // DCAP costs collateral round-trips, so a mistyped path should not be
    // discovered on the far side of them.
    let record_bytes = read_record(&cli.record).await?;
    let record: HarvestRecord =
        serde_json::from_slice(&record_bytes).context("--record is not a harvest record")?;
    let policy = load_policy(&cli.common.policy).await?;
    let collateral = match &cli.collateral {
        Some(path) => HarvestCollateral::Archived(Box::new(read_archived_collateral(path).await?)),
        None => HarvestCollateral::Live {
            pccs_url: cli.common.pccs_url,
        },
    };

    let verified = verify_harvest(record, policy, collateral).await?;
    // After the verdict, never before: a burned harvest must not leave a
    // half-archive behind for a later reader to trust.
    if let Some(path) = &cli.dump_collateral {
        let document = verified.archived_collateral()?;
        tokio::fs::write(path, document)
            .await
            .with_context(|| format!("writing --dump-collateral {}", path.display()))?;
    }
    Ok(verified.to_json().to_string())
}

async fn run_deploy(cli: DeployCli) -> anyhow::Result<String> {
    // Read every local input before contacting the node: a mistyped path
    // should not be discovered on the far side of an RPC round-trip.
    let manifest_bytes = tokio::fs::read(&cli.manifest)
        .await
        .with_context(|| format!("reading --manifest {}", cli.manifest.display()))?;
    let policy = load_policy(&cli.common.policy).await?;

    let verified =
        verify_deploy(&cli.endpoint, &manifest_bytes, policy, cli.common.pccs_url).await?;
    Ok(verified.to_json().to_string())
}

/// Load the measurement policy, failing closed: this binary has no accept-any
/// path, so an unparseable policy must stop the run rather than widen it.
async fn load_policy(path: &Path) -> anyhow::Result<SeismicMeasurementPolicy> {
    SeismicMeasurementPolicy::from_file(path.to_path_buf())
        .await
        .with_context(|| format!("loading measurement policy {}", path.display()))
}

/// Read the archived collateral snapshot `--collateral` names.
///
/// Both failures are the flag's, not the founding's: a reader who mistypes the
/// path must not be told the quote failed to verify.
async fn read_archived_collateral(path: &Path) -> anyhow::Result<ArchivedSnapshot> {
    let document = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("reading --collateral {}", path.display()))?;
    collateral::parse(&document).with_context(|| {
        format!(
            "--collateral {} is not an archived snapshot",
            path.display()
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

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

    const NO_ATTESTATION: &str = r#"{ "attestation_type": "none", "attestation": [] }"#;

    fn write_file(dir: &tempfile::TempDir, name: &str, contents: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).expect("writing test input");
        path
    }

    /// A harvest record carrying `evidence` verbatim.
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
        let record = write_file(&dir, "node-1.json", &record_json(NO_ATTESTATION));
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
}
