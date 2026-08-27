//! `seismic-manifest` — the network-manifest tool for non-Rust deploy tooling.
//!
//! Two subcommands over one strict parser:
//!
//! - `render <doc>`: a manifest document in any JSON formatting → the
//!   canonical `network-manifest.json` bytes on stdout. The document is
//!   strictly parsed first, so invalid values never render.
//! - `parse <file>`: put existing manifest bytes through that same parser and
//!   answer with the exit code.
//!
//! `-` reads stdin. `render` is the only subcommand that writes to stdout, and
//! only on success: every failure is a message on stderr, a nonzero exit, and
//! nothing on stdout. Rust consumers link this crate's library instead; the
//! binary exists only for the subprocess boundary.

use clap::{Parser, Subcommand};
use seismic_manifest::{NetworkManifestV1, render};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "seismic-manifest", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Render a manifest document (any JSON formatting) as the canonical
    /// network-manifest.json bytes on stdout, after a strict schema parse.
    Render {
        /// Path to the manifest document (`-` for stdin).
        document: PathBuf,
    },
    /// Put a network-manifest.json through the strict v1 parser, the one
    /// every node reads the file with. Exit 0 if it parses; no stdout.
    Parse {
        /// Path to the manifest file (`-` for stdin).
        manifest: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Render { document } => {
            let bytes = read_input(&document)?;
            let manifest = NetworkManifestV1::from_json_bytes(&bytes).map_err(|e| e.to_string())?;
            write_stdout(&render(&manifest))
        }
        Command::Parse { manifest } => {
            let bytes = read_input(&manifest)?;
            NetworkManifestV1::from_json_bytes(&bytes).map_err(|e| e.to_string())?;
            Ok(())
        }
    }
}

fn read_input(path: &Path) -> Result<Vec<u8>, String> {
    if path == Path::new("-") {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| format!("reading stdin: {e}"))?;
        return Ok(buf);
    }
    std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))
}

fn write_stdout(bytes: &[u8]) -> Result<(), String> {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|()| stdout.flush())
        .map_err(|e| format!("writing stdout: {e}"))
}
