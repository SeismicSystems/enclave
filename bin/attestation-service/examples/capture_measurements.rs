//! Fetch and verify a remote node's attestation evidence, and record the guest
//! measurements it actually reports.
//!
//! Unlike `seismic-attestation`'s `azure_vtpm_roundtrip`, this never touches a
//! local TPM: it only *verifies* a remote quote. So it runs anywhere Linux runs
//! — a container on a laptop — pointed at a node's public address, and works
//! against a production image that has no shell.
//!
//! ```text
//! cargo run -p seismic-attestation-service --example capture_measurements -- \
//!   --url http://<node>:7878 \
//!   --manifest /path/to/network-manifest.json \
//!   --out-policy /tmp/observed.json
//! ```
//!
//! All 24 registers are always printed. `--out-policy` writes only the
//! admission-schema registers (Azure v1: pcr4, pcr9, pcr11), because a policy
//! file enforces every register it lists and must therefore match what the
//! admission ID covers. `--pcrs` overrides the set for experiments.
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
//! custodian to answer — that is, a node that has finished bootstrapping. PCRs
//! are final long before then, so use the on-node `azure_vtpm_roundtrip` to
//! measure a node that never got that far.

use anyhow::Context as _;
use clap::Parser;
use jsonrpsee::http_client::HttpClientBuilder;
use seismic_attestation::{
    AttestationType, NetworkId, SeismicMeasurementPolicy, VerifiedSeismicAttestation,
    VerifyOptions,
    bindings::{binding64_from_digest32, tx_io_binding},
    verify_evidence_with_options,
};
use seismic_attestation_rpc::AttestationRpcClient;
use std::collections::BTreeMap;

#[derive(Debug, Parser)]
#[command(about = "Fetch, verify, and record a remote node's guest measurements")]
struct Cli {
    /// Base URL of the node's attestation RPC, e.g. `http://<node>:7878`.
    #[arg(long)]
    url: String,

    /// Network manifest whose `network_id` the node is expected to have loaded.
    /// Used to recompute the evidence binding.
    #[arg(long, value_name = "PATH", required_unless_present = "network_id")]
    manifest: Option<std::path::PathBuf>,

    /// The expected `network_id` as hex, instead of `--manifest`. The id is the
    /// manifest's SHA-256, so `sha256sum network-manifest.json` produces it
    /// without having to copy the manifest to this host.
    #[arg(long, value_name = "HEX", conflicts_with = "manifest")]
    network_id: Option<String>,

    /// tx-io key epoch to request.
    #[arg(long, default_value_t = 0)]
    epoch: u64,

    /// Enforce this measurements file instead of accepting whatever the node
    /// reports. Without it, any measurements are accepted so they can be
    /// recorded — cryptographic verification still applies either way.
    #[arg(long, value_name = "PATH")]
    measurements: Option<std::path::PathBuf>,

    /// Restrict the emitted policy to these registers, e.g. `4,9,11`. Defaults
    /// to the Azure v1 schema set.
    ///
    /// Do not add pcr6 or pcr10: both carry per-VM-instance data, so a policy
    /// containing either matches exactly one node.
    #[arg(long, value_name = "LIST")]
    pcrs: Option<String>,

    /// Write the verified registers as a measurements-file policy record, in
    /// the same shape `--measurements` consumes.
    #[arg(long, value_name = "PATH")]
    out_policy: Option<std::path::PathBuf>,

    /// `measurement_id` for the emitted policy record.
    #[arg(long, value_name = "ID", default_value = "observed")]
    measurement_id: String,

    /// Optional PCCS URL for DCAP collateral.
    #[arg(long)]
    pccs_url: Option<String>,

    /// Allow the Azure outdated-TCB override path.
    #[arg(long)]
    override_azure_outdated_tcb: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    let network_id = resolve_network_id(&args).await?;
    println!("Expecting network_id {network_id}");

    println!("Fetching tx-io attestation evidence from {}...", args.url);
    let client = HttpClientBuilder::default().build(&args.url)?;
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

    // Recompute the binding the node should have used. This is what ties the
    // evidence to this network, this key, and this epoch.
    let expected_binding = binding64_from_digest32(tx_io_binding(
        &network_id,
        &response.tx_io_pk.serialize(),
        response.epoch,
    ));

    let policy = match &args.measurements {
        Some(path) => SeismicMeasurementPolicy::from_file(path.clone()).await?,
        None => {
            SeismicMeasurementPolicy::dangerously_accept_any_for_testing(AttestationType::AzureTdx)
        }
    };

    println!("Verifying evidence...");
    let verified = verify_evidence_with_options(
        response.evidence,
        expected_binding,
        policy,
        VerifyOptions {
            pccs_url: args.pccs_url,
            dump_dcap_quotes: false,
            override_azure_outdated_tcb: args.override_azure_outdated_tcb,
        },
    )
    .await?;
    println!("Verification succeeded.");

    let pcrs = sorted_azure_pcrs(&verified)
        .ok_or_else(|| anyhow::anyhow!("expected an Azure TDX attestation, got {verified:?}"))?;
    print_pcrs(&pcrs);

    if let Some(path) = &args.out_policy {
        let selected = select_pcrs(&pcrs, args.pcrs.as_deref())?;
        write_policy_record(path, &args.measurement_id, &selected).await?;
    }

    Ok(())
}

/// The `network_id` the node's evidence must be bound to, from either the
/// manifest itself or its already-computed hash.
async fn resolve_network_id(args: &Cli) -> anyhow::Result<NetworkId> {
    if let Some(hex_id) = &args.network_id {
        let bytes: [u8; 32] = hex::decode(hex_id.trim_start_matches("0x"))
            .context("--network-id is not valid hex")?
            .try_into()
            .map_err(|bytes: Vec<u8>| {
                anyhow::anyhow!("--network-id must be 32 bytes, got {}", bytes.len())
            })?;
        return Ok(NetworkId::from_bytes(bytes));
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

/// Azure PCRs as a `BTreeMap`, so output is ordered and diffable across nodes,
/// boots, and builds. The backend hands back a `HashMap`, whose iteration order
/// is not stable.
fn sorted_azure_pcrs(verified: &VerifiedSeismicAttestation) -> Option<BTreeMap<u32, [u8; 32]>> {
    match verified {
        VerifiedSeismicAttestation::AzureTdx(azure) => Some(
            azure
                .guest_measurements
                .pcrs
                .iter()
                .map(|(index, value)| (*index, *value))
                .collect(),
        ),
        _ => None,
    }
}

fn print_pcrs(pcrs: &BTreeMap<u32, [u8; 32]>) {
    println!("\nQuoted PCRs (SHA-256), {} registers:", pcrs.len());
    for (index, value) in pcrs {
        let marker = if value == &[0u8; 32] { "  (zero)" } else { "" };
        println!("  pcr{index:<2} = {}{marker}", hex::encode(value));
    }
    println!();
}

/// Registers bound by admission schema `seismic.azure-tdx.pcr4-pcr9-pcr11.v1`.
const AZURE_V1_SCHEMA_PCRS: [u32; 3] = [4, 9, 11];

/// Pick the registers to emit: an explicit `4,9,11`-style list, or the Azure
/// v1 schema set by default.
///
/// The default is the *schema*, deliberately not a "whatever is non-zero"
/// heuristic. A policy file enforces every register it lists, so it must
/// contain exactly the registers the admission ID covers, or the joiner and
/// the responder end up checking different things. Selecting by observed
/// value would also sweep in registers that cannot appear in a policy at all:
/// pcr6 and pcr10 differ per VM instance, and pcr17-22 read all-ones rather
/// than zero because they are uninitialised DRTM registers.
fn select_pcrs(
    pcrs: &BTreeMap<u32, [u8; 32]>,
    requested: Option<&str>,
) -> anyhow::Result<BTreeMap<u32, [u8; 32]>> {
    let indices: Vec<u32> = match requested {
        Some(list) => {
            list.split(',')
                .map(|entry| {
                    let entry = entry.trim();
                    entry.trim_start_matches("pcr").parse::<u32>().map_err(|_| {
                        anyhow::anyhow!("--pcrs entry is not a register index: {entry}")
                    })
                })
                .collect::<anyhow::Result<Vec<u32>>>()?
        }
        None => AZURE_V1_SCHEMA_PCRS.to_vec(),
    };

    indices
        .into_iter()
        .map(|index| {
            let value = *pcrs
                .get(&index)
                .ok_or_else(|| anyhow::anyhow!("pcr{index} is not present in the quote"))?;
            if value == [0u8; 32] {
                eprintln!("warning: pcr{index} is all-zero — nothing extended it");
            } else if value == [0xffu8; 32] {
                eprintln!("warning: pcr{index} is all-ones — uninitialised, not a measurement");
            }
            Ok((index, value))
        })
        .collect()
}

async fn write_policy_record(
    path: &std::path::Path,
    measurement_id: &str,
    pcrs: &BTreeMap<u32, [u8; 32]>,
) -> anyhow::Result<()> {
    let measurements: serde_json::Map<String, serde_json::Value> = pcrs
        .iter()
        .map(|(index, value)| {
            (
                format!("pcr{index}"),
                serde_json::json!({ "expected_any": [hex::encode(value)] }),
            )
        })
        .collect();

    let record = serde_json::json!([{
        "measurement_id": measurement_id,
        "attestation_type": AttestationType::AzureTdx.as_str(),
        "measurements": measurements,
    }]);

    tokio::fs::write(path, serde_json::to_vec_pretty(&record)?).await?;
    println!(
        "Wrote observed policy record ({} registers) to {}",
        pcrs.len(),
        path.display()
    );
    Ok(())
}
