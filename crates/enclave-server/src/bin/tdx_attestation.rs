//! Binary to retrieve and display TDX attestation

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};

fn main() -> Result<()> {
    println!("=== TDX Attestation Tool ===\n");

    // Report data must be exactly 64 bytes for TDX attestation
    // Using base64 encoded 64 zero bytes for a basic attestation
    let report_data_bytes = [0u8; 64];
    let report_data = STANDARD.encode(&report_data_bytes);

    println!("Report Data (base64): {}", report_data);
    println!();

    // Get TDX report
    println!("Getting TDX TD Report...");
    match tdx_attest::get_td_report(report_data.clone()) {
        Ok(td_report) => {
            println!("✓ TDX TD Report retrieved successfully");
            println!("  Length: {} bytes", td_report.len());
            println!("  Hex: {}", hex::encode(&td_report));
            println!("  Base64: {}", STANDARD.encode(&td_report));
            println!();
        }
        Err(e) => {
            eprintln!("✗ Failed to get TD report: {}", e);
            println!();
        }
    }

    // Get TDX quote
    println!("Getting TDX Quote...");
    match tdx_attest::get_tdx_quote(report_data) {
        Ok(tdx_quote) => {
            println!("✓ TDX Quote retrieved successfully");
            println!("  Length: {} bytes", tdx_quote.len());
            println!("  Hex: {}", hex::encode(&tdx_quote));
            println!("  Base64: {}", STANDARD.encode(&tdx_quote));
            println!();
        }
        Err(e) => {
            eprintln!("✗ Failed to get TDX quote: {}", e);
            eprintln!("  Note: TDX Quote generation may require additional hardware/software support");
            println!();
        }
    }

    Ok(())
}
