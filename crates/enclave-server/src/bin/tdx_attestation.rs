//! Binary to retrieve and display TDX attestation

use anyhow::Result;

fn main() -> Result<()> {
    // Report data can be any custom data you want to include in the attestation
    // Using an empty string for a basic attestation
    let report_data = String::new();

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
