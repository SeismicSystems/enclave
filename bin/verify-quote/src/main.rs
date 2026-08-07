//! `verify-quote` — DCAP-verify one founding node's summit-keys harvest quote.
//!
//! Checks that a quote's `report_data` is
//! `founding_summit_keys_binding(harvest_nonce, node_pk, consensus_pk)` for the
//! nonce and pubkeys given on the command line, that the quote verifies
//! cryptographically, and that its measurements satisfy the given measurement
//! policy. The binding is per node, so one run covers one node's harvest.
//!
//! ```text
//! verify-quote \
//!   --evidence harvest/box-1.evidence.json \
//!   --policy build/measurements.json \
//!   --nonce <64-hex> \
//!   --node-pubkey <64-hex> \
//!   --consensus-pubkey <96-hex>
//! ```
//!
//! `--evidence` is a JSON-serialized [`AttestationExchangeMessage`]; `-` reads
//! it from stdin. Exit 0 plus one JSON object on stdout means verified. Every
//! failure — bad input, binding mismatch, measurement mismatch, DCAP failure,
//! non-Azure evidence — is an error on stderr with a nonzero exit and nothing on
//! stdout.
//!
//! Verification-only: this never touches a local TPM. Azure TDX verification
//! is pure computation over the evidence bytes (the `azure-verifier` feature
//! of the `attestation` backend), so it builds and runs anywhere, including
//! macOS.

use anyhow::Context as _;
use clap::Parser;
use seismic_attestation::{
    AttestationType, SeismicMeasurementPolicy, VerifiedAzureAttestation, VerifyOptions,
    bindings::{binding64_from_digest32, founding_summit_keys_binding},
    verify_azure_evidence_with_options,
};
use std::{
    collections::BTreeMap,
    io::Read as _,
    path::{Path, PathBuf},
};

#[derive(Debug, Parser)]
#[command(
    name = "verify-quote",
    version,
    about = "DCAP-verify one founding node's summit-keys harvest quote against the intended image \
             measurements",
    long_about = "DCAP-verify one founding node's summit-keys harvest quote against the intended \
                  image measurements.\n\n\
                  Recomputes the report_data the key holder must have quoted over \
                  (founding_summit_keys_binding of --nonce, --node-pubkey, --consensus-pubkey), \
                  verifies \
                  the evidence cryptographically, and enforces --policy on the quoted \
                  measurements. The policy is required: there is no accept-any mode, because the \
                  measurement check is the point.\n\n\
                  Exit 0 with a single JSON object on stdout means verified: \
                  {\"verified\": true, \"attestation_type\": ..., \"binding\": <128-hex \
                  report_data>, \"pcrs\": {\"pcr4\": <64-hex>, ...}}. The pcrs map carries every \
                  register the quote covers, not just the ones the policy pins, so the caller can \
                  archive it as harvest provenance. Any failure — unreadable or malformed input, \
                  binding mismatch, measurement mismatch, DCAP failure, non-Azure evidence — \
                  prints an error to stderr and exits nonzero, with nothing on stdout.\n\n\
                  Verification-only: this never touches a local TPM, and Azure TDX verification \
                  is pure computation over the evidence bytes, so it builds and runs anywhere, \
                  including macOS."
)]
struct Cli {
    /// JSON-serialized AttestationExchangeMessage the key holder served
    /// (`-` reads stdin).
    #[arg(long, value_name = "PATH")]
    evidence: PathBuf,

    /// Measurement-policy JSON pinning the intended image measurements, e.g.
    /// seismic-images' `build/measurements.json`. Required: a quote from an
    /// unintended image must not pass.
    #[arg(long, value_name = "PATH")]
    policy: PathBuf,

    /// The harvest nonce this quote was requested with (32 bytes hex).
    #[arg(long, value_name = "HEX")]
    nonce: String,

    /// The ed25519 node pubkey the key holder returned (32 bytes hex).
    #[arg(long, value_name = "HEX")]
    node_pubkey: String,

    /// The BLS12-381 MinPk consensus pubkey the key holder returned
    /// (48 bytes hex).
    #[arg(long, value_name = "HEX")]
    consensus_pubkey: String,

    /// Optional PCCS URL for DCAP collateral, instead of the backend default.
    #[arg(long, value_name = "URL")]
    pccs_url: Option<String>,

    /// Allow the backend's Azure outdated-TCB override path.
    #[arg(long)]
    override_azure_outdated_tcb: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Returning the error from main sends it to stderr with a nonzero exit and
    // leaves stdout empty, which is exactly deploy's contract.
    println!("{}", run(Cli::parse()).await?);
    Ok(())
}

/// Verify the harvest quote described by `cli` and render the success report.
///
/// Separate from `main` so the whole path — including every rejection — is
/// callable from tests.
async fn run(cli: Cli) -> anyhow::Result<String> {
    // Resolve everything that can fail on bad input before any verification:
    // DCAP costs collateral round-trips, so a mistyped pubkey should not be
    // discovered on the far side of them.
    let nonce = decode_hex_arg::<32>("--nonce", &cli.nonce)?;
    let node_pk = decode_hex_arg::<32>("--node-pubkey", &cli.node_pubkey)?;
    let consensus_pk = decode_hex_arg::<48>("--consensus-pubkey", &cli.consensus_pubkey)?;
    let binding = harvest_binding(&nonce, &node_pk, &consensus_pk);

    let evidence_bytes = read_evidence(&cli.evidence).await?;
    let evidence = serde_json::from_slice(&evidence_bytes)
        .context("--evidence is not a JSON-serialized AttestationExchangeMessage")?;

    let policy = SeismicMeasurementPolicy::from_file(cli.policy.clone())
        .await
        .with_context(|| format!("loading measurement policy {}", cli.policy.display()))?;

    let verified = verify_azure_evidence_with_options(
        evidence,
        binding,
        policy,
        VerifyOptions {
            pccs_url: cli.pccs_url,
            dump_dcap_quotes: false,
            override_azure_outdated_tcb: cli.override_azure_outdated_tcb,
        },
    )
    .await
    .context("verifying harvest evidence")?;

    Ok(report(&verified))
}

/// The 64-byte `report_data` a harvested quote must carry.
///
/// Pure and deliberately trivial: deploy calls this instead of deriving the
/// binding itself, so this one line is the single definition of the check on
/// both sides.
fn harvest_binding(nonce: &[u8; 32], node_pk: &[u8; 32], consensus_pk: &[u8; 48]) -> [u8; 64] {
    binding64_from_digest32(founding_summit_keys_binding(nonce, node_pk, consensus_pk))
}

/// Decode a fixed-length hex argument, naming the flag in every failure.
///
/// The caller is a script assembling five hex strings; an error that does not
/// say which one it means costs a round of guessing.
fn decode_hex_arg<const N: usize>(flag: &str, value: &str) -> anyhow::Result<[u8; N]> {
    let bare = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(bare).with_context(|| format!("{flag} is not valid hex"))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            "{flag} must be {N} bytes ({} hex chars), got {}",
            N * 2,
            bytes.len()
        )
    })
}

/// Read the evidence document from a path, or stdin for `-` (the subprocess
/// boundary deploy uses to pass exact bytes without a temp file).
async fn read_evidence(path: &Path) -> anyhow::Result<Vec<u8>> {
    if path == Path::new("-") {
        let mut bytes = Vec::new();
        std::io::stdin()
            .read_to_end(&mut bytes)
            .context("reading --evidence from stdin")?;
        return Ok(bytes);
    }
    tokio::fs::read(path)
        .await
        .with_context(|| format!("reading --evidence {}", path.display()))
}

/// The success report: one JSON object, printed only once verification passed.
///
/// Registers come out of a `BTreeMap` so the object is assembled in register
/// order and archived reports diff cleanly across nodes, boots, and builds (the
/// backend hands back a `HashMap`, whose iteration order is not stable). Every
/// quoted register is included, not just the policy's, because the caller keeps
/// this output as harvest provenance.
fn report(verified: &VerifiedAzureAttestation) -> String {
    let pcrs: serde_json::Map<String, serde_json::Value> = verified
        .guest_measurements
        .pcrs
        .iter()
        .map(|(index, value)| (*index, *value))
        .collect::<BTreeMap<u32, [u8; 32]>>()
        .into_iter()
        .map(|(index, value)| (format!("pcr{index}"), hex::encode(value).into()))
        .collect();

    serde_json::json!({
        "verified": true,
        "attestation_type": AttestationType::AzureTdx.as_str(),
        "binding": hex::encode(verified.binding),
        "pcrs": pcrs,
    })
    .to_string()
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

    const NONCE_HEX: &str = "7777777777777777777777777777777777777777777777777777777777777777";
    const NODE_PK_HEX: &str = "8888888888888888888888888888888888888888888888888888888888888888";
    const CONSENSUS_PK_HEX: &str = "999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999";

    fn write_file(dir: &tempfile::TempDir, name: &str, contents: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).expect("writing test input");
        path
    }

    fn cli(evidence: &Path, policy: &Path) -> Cli {
        Cli::try_parse_from([
            "verify-quote".as_ref(),
            "--evidence".as_ref(),
            evidence.as_os_str(),
            "--policy".as_ref(),
            policy.as_os_str(),
            "--nonce".as_ref(),
            NONCE_HEX.as_ref(),
            "--node-pubkey".as_ref(),
            NODE_PK_HEX.as_ref(),
            "--consensus-pubkey".as_ref(),
            CONSENSUS_PK_HEX.as_ref(),
        ])
        .expect("well-formed argv")
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    /// The binding is a wire-format commitment shared with the key holder and
    /// with deploy's assemble-time re-check, so this vector is frozen: it is
    /// `founding_summit_keys_binding`'s frozen digest, zero-padded to 64 bytes.
    #[test]
    fn harvest_binding_matches_frozen_vector() {
        let binding = harvest_binding(&[0x77; 32], &[0x88; 32], &[0x99; 48]);

        assert_eq!(
            hex::encode(&binding[..32]),
            "8973b984dc10f809ebfaacdcad64b8cc5a647cf24e4bc27b3833cc234a9290e5"
        );
        assert_eq!(&binding[32..], &[0u8; 32]);
    }

    /// The hex flags feed the binding, and a wrong one produces a mismatch that
    /// looks exactly like a bad quote — so they are rejected up front, by name.
    #[test]
    fn hex_args_fail_by_flag_name() {
        let not_hex = decode_hex_arg::<32>("--nonce", "zz77")
            .unwrap_err()
            .to_string();
        assert!(not_hex.contains("--nonce"), "{not_hex}");

        let wrong_length = decode_hex_arg::<48>("--consensus-pubkey", NODE_PK_HEX)
            .unwrap_err()
            .to_string();
        assert!(
            wrong_length.contains("--consensus-pubkey"),
            "{wrong_length}"
        );
        assert!(wrong_length.contains("48 bytes"), "{wrong_length}");

        assert_eq!(
            decode_hex_arg::<32>("--node-pubkey", NODE_PK_HEX).unwrap(),
            [0x88; 32]
        );
        // Deploy may hand over 0x-prefixed hex; the two forms mean the same key.
        assert_eq!(
            decode_hex_arg::<32>("--node-pubkey", &format!("0x{NODE_PK_HEX}")).unwrap(),
            [0x88; 32]
        );
    }

    #[tokio::test]
    async fn malformed_evidence_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let evidence = write_file(&dir, "evidence.json", "{ not evidence");
        let policy = write_file(&dir, "policy.json", VALID_POLICY);

        let error = run(cli(&evidence, &policy)).await.unwrap_err().to_string();
        assert!(error.contains("--evidence"), "{error}");
    }

    #[tokio::test]
    async fn missing_evidence_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let policy = write_file(&dir, "policy.json", VALID_POLICY);

        let error = run(cli(&dir.path().join("absent.json"), &policy))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("reading --evidence"), "{error}");
    }

    /// Fail-closed on the policy: this binary has no accept-any path, so an
    /// unparseable policy must stop the run rather than widen it.
    #[tokio::test]
    async fn malformed_policy_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let evidence = write_file(
            &dir,
            "evidence.json",
            r#"{ "attestation_type": "azure-tdx", "attestation": [1, 2, 3] }"#,
        );
        let policy = write_file(&dir, "policy.json", "{ not a policy");

        let error = run(cli(&evidence, &policy)).await.unwrap_err().to_string();
        assert!(error.contains("measurement policy"), "{error}");
    }

    /// One job, one binding: a quote from a platform whose measurements this
    /// policy format cannot pin is rejected without any collateral fetching.
    #[tokio::test]
    async fn non_azure_evidence_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let evidence = write_file(
            &dir,
            "evidence.json",
            r#"{ "attestation_type": "none", "attestation": [] }"#,
        );
        let policy = write_file(&dir, "policy.json", VALID_POLICY);

        assert!(run(cli(&evidence, &policy)).await.is_err());
    }

    #[test]
    fn report_carries_every_quoted_register() {
        let verified = VerifiedAzureAttestation {
            binding: harvest_binding(&[0x77; 32], &[0x88; 32], &[0x99; 48]),
            guest_measurements: AzureGuestMeasurements {
                pcrs: HashMap::from([(11, [0xbb; 32]), (4, [0x44; 32]), (9, [0x99; 32])]),
            },
        };

        let report: serde_json::Value = serde_json::from_str(&report(&verified)).unwrap();

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
}
