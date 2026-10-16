//! Verify a node's attestation evidence and record the guest measurements it
//! actually reports, on Azure or GCP.
//!
//! Unlike `seismic-attestation`'s `azure_vtpm_roundtrip`, this never touches a
//! local TPM: it only *verifies* a quote. So it runs anywhere Linux runs, a
//! container on a laptop, pointed at a node's public address, and works
//! against a production image that has no shell.
//!
//! ```text
//! cargo run -p seismic-attestation-service --example capture_measurements -- \
//!   --url http://<node>:7878 \
//!   --manifest /path/to/network-manifest.json \
//!   --out-policy /tmp/observed.json
//! ```
//!
//! Every quoted register is printed: the 24 vTPM PCRs on Azure, MRTD and the
//! four RTMRs on GCP. `--out-policy` writes the admission-schema record for
//! the platform the evidence came from (Azure v1: pcr4, pcr9, pcr11; GCP v1:
//! rtmr1, rtmr2) through measurement-admission's promotion, so it carries
//! exactly the registers the admission ID covers.
//!
//! The manifest is only read to derive `network_id`, which is its SHA-256. When
//! the manifest isn't on this host, pass the hash instead — verification is
//! identical either way:
//!
//! ```text
//!   --network-id 0x$(sha256sum network-manifest.json | cut -d' ' -f1)
//! ```
//!
//! Diff the emitted record against a `make measure` prediction to see whether
//! the booted image measures what the build predicted:
//!
//! ```text
//! diff <(jq -S . /tmp/observed.json) <(jq -S . build/measurements.json)
//! ```
//!
//! The node binds its tx-io evidence to `tx_io_binding(network_id, tx_io_pk,
//! epoch)` rather than to a caller-chosen nonce, so the expected binding is
//! recomputed here from the manifest's `network_id`, the key the node returned,
//! and the requested epoch. A node advertising a different key, epoch, or
//! network fails verification.
//!
//! Note this reaches the node over its attestation RPC, which needs a live
//! custodian to answer, that is, a node that has finished bootstrapping. A
//! node that has not been founded yet serves the founding harvest instead;
//! save its `/v1/quote` response and verify that:
//!
//! ```text
//! nonce=$(openssl rand -hex 32)
//! curl -s "http://<node>:7879/v1/quote?nonce=$nonce" > /tmp/quote.json
//! cargo run -p seismic-attestation-service --example capture_measurements -- \
//!   --harvest-response /tmp/quote.json --nonce $nonce --out-policy /tmp/observed.json
//! ```
//!
//! The harvest binds the evidence to the nonce and the keys the response
//! carries, so the binding is recomputed from those.

use anyhow::Context as _;
use clap::Parser;
use jsonrpsee::http_client::HttpClientBuilder;
use seismic_attestation::{
    AttestationExchangeMessage, AttestationType, NetworkId, SeismicMeasurementPolicy,
    TdxMeasurements, VerifiedSeismicAttestation, VerifyOptions,
    bindings::{binding64_from_digest32, founding_keys_binding, tx_io_binding},
    verify_evidence_with_policy,
};
use seismic_attestation_rpc::AttestationRpcClient;
use seismic_attestation_service::harvest::QuoteResponse;
use seismic_measurement_admission::promote_measurements;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(about = "Verify a node's evidence and record its guest measurements")]
struct Cli {
    /// Base URL of the node's attestation RPC, e.g. `http://<node>:7878`.
    #[arg(long, required_unless_present = "harvest_response")]
    url: Option<String>,

    /// Network manifest whose `network_id` the node is expected to have loaded.
    /// Used to recompute the evidence binding.
    #[arg(
        long,
        value_name = "PATH",
        required_unless_present_any = ["network_id", "harvest_response"],
        conflicts_with = "harvest_response"
    )]
    manifest: Option<PathBuf>,

    /// The expected `network_id` as hex, instead of `--manifest`. The id is the
    /// manifest's SHA-256, so `sha256sum network-manifest.json` produces it
    /// without having to copy the manifest to this host.
    #[arg(long, value_name = "HEX", conflicts_with_all = ["manifest", "harvest_response"])]
    network_id: Option<String>,

    /// tx-io key epoch to request.
    #[arg(long, default_value_t = 0, conflicts_with = "harvest_response")]
    epoch: u64,

    /// A founding-harvest `/v1/quote` response saved to a file, verified
    /// instead of fetching tx-io evidence from `--url`. Needs `--nonce`.
    #[arg(long, value_name = "PATH", requires = "nonce", conflicts_with = "url")]
    harvest_response: Option<PathBuf>,

    /// The nonce the harvest response was requested with, 32 bytes of hex.
    #[arg(long, value_name = "HEX", requires = "harvest_response")]
    nonce: Option<String>,

    /// Enforce this measurements file instead of accepting whatever the node
    /// reports. Without it, any measurements are accepted so they can be
    /// recorded — cryptographic verification still applies either way.
    #[arg(long, value_name = "PATH")]
    measurements: Option<PathBuf>,

    /// Write the verified registers as a measurements-file policy record, in
    /// the same shape `--measurements` consumes.
    #[arg(long, value_name = "PATH")]
    out_policy: Option<PathBuf>,

    /// `measurement_id` for the emitted policy record.
    #[arg(long, value_name = "ID", default_value = "observed")]
    measurement_id: String,

    /// Optional PCCS URL for DCAP collateral.
    #[arg(long)]
    pccs_url: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    let (evidence, expected_binding) = match &args.harvest_response {
        Some(path) => {
            harvest_evidence(path, args.nonce.as_deref().expect("clap requires --nonce"))?
        }
        None => tx_io_evidence(&args).await?,
    };

    let attestation_type = evidence.attestation_type();
    println!("Evidence declares {attestation_type}");
    let policy = match &args.measurements {
        Some(path) => SeismicMeasurementPolicy::from_file(path.clone()).await?,
        None => SeismicMeasurementPolicy::dangerously_accept_any_for_testing(attestation_type),
    };

    println!("Verifying evidence...");
    let verified = verify_evidence_with_policy(
        evidence,
        expected_binding,
        policy,
        VerifyOptions {
            pccs_url: args.pccs_url,
            ..Default::default()
        },
    )
    .await?
    .attestation;
    println!("Verification succeeded.");

    let registers = quoted_registers(&verified);
    print_registers(&registers);

    if let Some(path) = &args.out_policy {
        write_policy_record(
            path,
            &args.measurement_id,
            verified.attestation_type(),
            &registers,
        )?;
    }

    Ok(())
}

/// The node's tx-io evidence over its attestation RPC, and the binding it
/// should have used: this network, this key, this epoch.
async fn tx_io_evidence(args: &Cli) -> anyhow::Result<(AttestationExchangeMessage, [u8; 64])> {
    let network_id = resolve_network_id(args).await?;
    println!("Expecting network_id {network_id}");

    let url = args.url.as_deref().expect("clap requires --url");
    println!("Fetching tx-io attestation evidence from {url}...");
    let client = HttpClientBuilder::default().build(url)?;
    let response = client
        .get_tx_io_attestation_evidence(args.epoch)
        .await
        .context("fetching tx-io attestation evidence")?;

    anyhow::ensure!(
        response.epoch == args.epoch,
        "node answered for epoch {}, expected {}",
        response.epoch,
        args.epoch
    );

    let binding = binding64_from_digest32(tx_io_binding(
        &network_id,
        &response.tx_io_pk.serialize(),
        response.epoch,
    ));
    Ok((response.evidence, binding))
}

/// A saved founding-harvest response, and the binding the harvest put in
/// the quote: the nonce and the three keys the response carries.
fn harvest_evidence(
    path: &Path,
    nonce: &str,
) -> anyhow::Result<(AttestationExchangeMessage, [u8; 64])> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let response: QuoteResponse = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not a /v1/quote response", path.display()))?;
    let nonce: [u8; 32] = decode_hex("--nonce", nonce)?;
    let node_pk: [u8; 32] = decode_hex("node_public_key", &response.node_public_key)?;
    let consensus_pk: [u8; 48] =
        decode_hex("consensus_public_key", &response.consensus_public_key)?;
    let candidate_tx_io_pk: [u8; 33] = decode_hex(
        "candidate_tx_io_public_key",
        &response.candidate_tx_io_public_key,
    )?;
    let binding = binding64_from_digest32(founding_keys_binding(
        &nonce,
        &node_pk,
        &consensus_pk,
        &candidate_tx_io_pk,
    ));
    Ok((response.evidence, binding))
}

/// The `network_id` the node's evidence must be bound to, from either the
/// manifest itself or its already-computed hash.
async fn resolve_network_id(args: &Cli) -> anyhow::Result<NetworkId> {
    if let Some(hex_id) = &args.network_id {
        return Ok(NetworkId::from_bytes(decode_hex("--network-id", hex_id)?));
    }

    let path = args
        .manifest
        .as_ref()
        .expect("clap requires --manifest or --network-id");
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("reading manifest {}", path.display()))?;
    Ok(NetworkId::from_manifest_bytes(&bytes))
}

fn decode_hex<const N: usize>(field: &str, value: &str) -> anyhow::Result<[u8; N]> {
    hex::decode(value.trim_start_matches("0x"))
        .with_context(|| format!("{field} is not valid hex"))?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("{field} must be {N} bytes, got {}", bytes.len()))
}

/// Every register the quote attests, named as a policy document spells it,
/// in register order so output is diffable across nodes, boots, and builds.
fn quoted_registers(verified: &VerifiedSeismicAttestation) -> Vec<(String, Vec<u8>)> {
    match verified {
        VerifiedSeismicAttestation::AzureTdx(azure) => azure
            .guest_measurements
            .pcrs
            .iter()
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .map(|(index, value)| (format!("pcr{index}"), value.to_vec()))
            .collect(),
        VerifiedSeismicAttestation::DcapTdx(tdx) | VerifiedSeismicAttestation::GcpTdx(tdx) => {
            let TdxMeasurements {
                mrtd,
                rtmr0,
                rtmr1,
                rtmr2,
                rtmr3,
            } = &tdx.measurements;
            [
                ("mrtd", mrtd),
                ("rtmr0", rtmr0),
                ("rtmr1", rtmr1),
                ("rtmr2", rtmr2),
                ("rtmr3", rtmr3),
            ]
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value.to_vec()))
            .collect()
        }
    }
}

fn print_registers(registers: &[(String, Vec<u8>)]) {
    println!("\nQuoted registers, {}:", registers.len());
    for (name, value) in registers {
        let marker = if value.iter().all(|byte| *byte == 0) {
            "  (zero)"
        } else if value.iter().all(|byte| *byte == 0xff) {
            "  (all-ones: uninitialised, not a measurement)"
        } else {
            ""
        };
        println!("  {name:<6} = {}{marker}", hex::encode(value));
    }
    println!();
}

/// Promote the quoted registers into the platform's admission-schema record,
/// the same way `make measure` output is promoted at image release.
fn write_policy_record(
    path: &Path,
    measurement_id: &str,
    attestation_type: AttestationType,
    registers: &[(String, Vec<u8>)],
) -> anyhow::Result<()> {
    // MRTD identifies the firmware, not the guest image; it is no policy key.
    let measurements: serde_json::Map<String, serde_json::Value> = registers
        .iter()
        .filter(|(name, _)| name.as_str() != "mrtd")
        .map(|(name, value)| {
            (
                name.clone(),
                serde_json::json!({ "expected": hex::encode(value) }),
            )
        })
        .collect();
    let raw = serde_json::json!({
        "attestation_type": attestation_type.as_str(),
        "measurement_id": measurement_id,
        "measurements": measurements,
    });
    let promoted =
        promote_measurements(&serde_json::to_vec(&raw)?, None, None).with_context(|| {
            format!("promoting the {attestation_type} registers to a policy record")
        })?;
    let bound = serde_json::from_slice::<serde_json::Value>(&promoted)?[0]["measurements"]
        .as_object()
        .map_or(0, |map| map.len());

    std::fs::write(path, &promoted).with_context(|| format!("writing {}", path.display()))?;
    println!(
        "Wrote the {attestation_type} policy record ({bound} registers) to {}",
        path.display()
    );
    Ok(())
}
