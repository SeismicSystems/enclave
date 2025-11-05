//! Binary to retrieve and display TDX attestation

use anyhow::Result;

fn main() -> Result<()> {
    // Get TDX report
    match tdx_attest::get_td_report() {
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
    match tdx_attest::get_tdx_quote() {
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
