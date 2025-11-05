//! Binary to retrieve and display TDX attestation

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};

fn main() -> Result<()> {
    // Report data must be exactly 64 bytes for TDX attestation
    // Using base64 encoded 64 zero bytes for a basic attestation
    let report_data_bytes = [0u8; 64];
    let report_data = STANDARD.encode(&report_data_bytes);

    // Get TDX report
    match tdx_attest::get_td_report(report_data.clone()) {
        Ok(td_report) => {
            println!("TDX TD Report:");
            println!("{:?}", td_report);
            println!();
        }
        Err(e) => {
            eprintln!("Failed to get TD report: {}", e);
        }
    }

    // Get TDX quote
    match tdx_attest::get_tdx_quote(report_data) {
        Ok(tdx_quote) => {
            println!("TDX Quote:");
            println!("{:?}", tdx_quote);
        }
        Err(e) => {
            eprintln!("Failed to get TDX quote: {}", e);
        }
    }

    Ok(())
}
