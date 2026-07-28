//! Policy-compiler CLI: exposes the shared admission implementation to
//! non-Rust deploy tooling; Rust consumers link the library directly, so
//! this binary exists only for the subprocess boundary. `promote` normalizes
//! raw `make measure` output into a policy document; `compile` turns a
//! measurement-policy document into admission IDs plus registry genesis
//! storage; `admission-id` derives the ID for one measured guest
//! (runbooks, debugging).

use alloy_primitives::B256;
use clap::{Parser, Subcommand};
use seismic_measurement_admission::{
    AzureTdxV1Measurements, CompileReport, compile_policy, promote_measurements,
};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "seismic-measurement-admission", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Promote raw `make measure` output into a measurement-policy document
    /// (JSON on stdout): one record binding exactly the schema registers,
    /// compiled before it is emitted. An input that already is a record
    /// list is compiled and passed through byte-verbatim.
    Promote {
        /// Path to the make-measure measurements file (`-` for stdin).
        measurements: PathBuf,
        /// Policy record id, conventionally the registered image artifact
        /// filename; overrides one stamped into the measurements file.
        #[arg(long)]
        measurement_id: Option<String>,
        /// Default attestation type when the measurements file carries none.
        #[arg(long)]
        attestation_type: Option<String>,
    },
    /// Compile a measurement-policy document into the admission IDs it
    /// admits and the registry genesis storage seeding them (JSON on stdout).
    Compile {
        /// Path to the measurement-policy.json document (`-` for stdin).
        policy: PathBuf,
    },
    /// Derive the admission ID for one measured Azure TDX guest
    /// (hex on stdout).
    AdmissionId {
        /// SHA-256 vTPM PCR4 digest (32 bytes hex, 0x optional).
        #[arg(long, value_parser = parse_word)]
        pcr4: B256,
        /// SHA-256 vTPM PCR9 digest (32 bytes hex, 0x optional).
        #[arg(long, value_parser = parse_word)]
        pcr9: B256,
        /// SHA-256 vTPM PCR11 digest (32 bytes hex, 0x optional).
        #[arg(long, value_parser = parse_word)]
        pcr11: B256,
    },
}

fn parse_word(value: &str) -> Result<B256, String> {
    let bare = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(bare)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .map(B256::from)
        .ok_or_else(|| format!("{value:?} is not 32 bytes of hex"))
}

/// Read an input document from a path, or stdin for `-` (the subprocess
/// boundary deploy tooling uses to pass exact bytes without temp files).
fn read_input(path: &Path) -> Result<Vec<u8>, String> {
    if path == Path::new("-") {
        let mut bytes = Vec::new();
        std::io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|e| format!("cannot read stdin: {e}"))?;
        return Ok(bytes);
    }
    std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn run(cli: Cli) -> Result<Vec<u8>, String> {
    match cli.command {
        Command::Promote {
            measurements,
            measurement_id,
            attestation_type,
        } => {
            let bytes = read_input(&measurements)?;
            promote_measurements(
                &bytes,
                measurement_id.as_deref(),
                attestation_type.as_deref(),
            )
            .map_err(|e| e.to_string())
        }
        Command::Compile { policy } => {
            let bytes = read_input(&policy)?;
            let compiled = compile_policy(&bytes).map_err(|e| e.to_string())?;
            Ok(CompileReport::new(&compiled).to_json().into_bytes())
        }
        Command::AdmissionId { pcr4, pcr9, pcr11 } => {
            let tuple = AzureTdxV1Measurements { pcr4, pcr9, pcr11 };
            Ok(format!("{}\n", tuple.admission_id()).into_bytes())
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(output) => {
            // Byte-verbatim: a passed-through policy document must reach
            // stdout exactly as it was read.
            if std::io::stdout().write_all(&output).is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}
