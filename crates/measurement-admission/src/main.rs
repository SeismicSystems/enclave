//! Policy-compiler CLI: exposes the shared admission implementation to
//! non-Rust deploy tooling; Rust consumers link the library directly, so
//! this binary exists only for the subprocess boundary. `compile` turns a
//! measurement-policy document into admission IDs plus registry genesis
//! storage; `admission-id` derives the ID for one measured guest
//! (runbooks, debugging).

use alloy_primitives::B256;
use clap::{Parser, Subcommand};
use seismic_measurement_admission::{AzureTdxV1Measurements, CompileReport, compile_policy};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "seismic-measurement-admission", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Compile a measurement-policy document into the admission IDs it
    /// admits and the registry genesis storage seeding them (JSON on stdout).
    Compile {
        /// Path to the measurement-policy.json document.
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

fn run(cli: Cli) -> Result<String, String> {
    match cli.command {
        Command::Compile { policy } => {
            let bytes = std::fs::read(&policy)
                .map_err(|e| format!("cannot read {}: {e}", policy.display()))?;
            let compiled = compile_policy(&bytes).map_err(|e| e.to_string())?;
            Ok(CompileReport::new(&compiled).to_json())
        }
        Command::AdmissionId { pcr4, pcr9, pcr11 } => {
            let tuple = AzureTdxV1Measurements { pcr4, pcr9, pcr11 };
            Ok(format!("{}\n", tuple.admission_id()))
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}
