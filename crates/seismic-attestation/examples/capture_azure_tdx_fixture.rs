//! Capture a real Azure TDX attestation fixture.
//!
//! Run this manually on an Azure TDX CVM with permission to access the vTPM
//! device. Root works everywhere; a non-root user may also work if the VM's udev
//! rules grant TPM access to a group such as `tss` and the user is in that
//! group. It writes a JSON fixture with the current Seismic evidence envelope
//! `{ hcl_report, quote }` plus derived fields useful for tests.
//!
//! Usage:
//!   cargo run -p seismic-attestation --example capture_azure_tdx_fixture -- \
//!     <binding-hex> [out.json]
//!
//! If TPM access is denied, rerun with `sudo` or fix the VM's TPM device group
//! permissions.
//!
//! `binding-hex` is the Seismic protocol binding to place in Azure HCL
//! `user-data`, e.g. a 32-byte SHA-256 digest.

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use az_tdx_vtpm::{hcl::HclReport, imds, tdx, vtpm};
    use dcap_rs::types::quotes::{body::QuoteBody, version_4::QuoteV4};
    use serde_json::json;
    use std::{env, fs};

    let mut args = env::args().skip(1);
    let Some(binding_hex) = args.next() else {
        eprintln!(
            "usage: capture_azure_tdx_fixture <binding-hex> [out.json]\n\
             example binding: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        std::process::exit(2);
    };
    let out_path = args.next();

    let binding = hex::decode(binding_hex.trim_start_matches("0x"))?;

    let hcl_report_bytes = vtpm::get_report_with_report_data(&binding)?;
    let hcl_report = HclReport::new(hcl_report_bytes.clone())?;
    let hcl_var_data = hcl_report.var_data().to_vec();
    let hcl_user_data = extract_hcl_user_data(&hcl_var_data)?;
    let hcl_var_data_sha256 = hcl_report.var_data_sha256();

    let td_report: tdx::TdReport = (&hcl_report).try_into()?;
    let td_report_report_data = td_report.report_mac.reportdata;

    let quote_bytes = imds::get_td_quote(&td_report)?;
    let quote = QuoteV4::from_bytes(&quote_bytes);
    let quote_report_data = match quote.quote_body {
        QuoteBody::TD10QuoteBody(body) => body.report_data,
        _ => return Err("IMDS returned non-TDX quote".into()),
    };

    let fixture = json!({
        "format": "seismic-azure-tdx-attestation-fixture-v1",
        "binding_hex": hex::encode(&binding),
        "hcl_report_hex": hex::encode(&hcl_report_bytes),
        "quote_hex": hex::encode(&quote_bytes),
        "hcl_var_data_hex": hex::encode(&hcl_var_data),
        "hcl_user_data_hex": hex::encode(&hcl_user_data),
        "hcl_var_data_sha256_hex": hex::encode(hcl_var_data_sha256),
        "td_report_report_data_hex": hex::encode(td_report_report_data),
        "quote_report_data_hex": hex::encode(quote_report_data),
        "checks": {
            "td_report_prefix_matches_hcl_var_data_sha256": td_report_report_data[..32] == hcl_var_data_sha256,
            "quote_prefix_matches_hcl_var_data_sha256": quote_report_data[..32] == hcl_var_data_sha256,
            "quote_report_data_matches_td_report": quote_report_data == td_report_report_data,
        }
    });

    let pretty = serde_json::to_string_pretty(&fixture)?;
    if let Some(out_path) = out_path {
        fs::write(&out_path, pretty)?;
        eprintln!("wrote fixture to {out_path}");
    } else {
        println!("{pretty}");
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn extract_hcl_user_data(var_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    #[derive(serde::Deserialize)]
    struct HclVarDataUserData {
        #[serde(rename = "user-data")]
        user_data: String,
    }

    let parsed: HclVarDataUserData = serde_json::from_slice(var_data)?;
    Ok(hex::decode(parsed.user_data.trim_start_matches("0x"))?)
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("capture_azure_tdx_fixture must be run on a Linux Azure TDX CVM");
    std::process::exit(1);
}
