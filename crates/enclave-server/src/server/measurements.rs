use az_tdx_vtpm::{hcl, imds, tdx, vtpm};
use dcap_rs::types::quotes::version_4::QuoteV4;
use serde::{Deserialize, Serialize};

pub fn print_measurements() {
    let bytes = vtpm::get_report().unwrap();
    let hcl_report = hcl::HclReport::new(bytes).unwrap();
    let var_data: &[u8] = hcl_report.var_data();

    println!("var_data: {var_data:?}");
    let td_report: tdx::TdReport = hcl_report.try_into().unwrap();
    println!("td report: \n {td_report:?}");

    let td_quote_bytes = imds::get_td_quote(&td_report).unwrap();
    let quote = QuoteV4::from_bytes(&td_quote_bytes);
    println!("QuoteV4: {quote:?}");

    let bytes = vtpm::get_report_with_report_data(&[1u8; 32]).unwrap();
    let hcl_report = hcl::HclReport::new(bytes).unwrap();

    let var_data = hcl_report.var_data();

    let decoded_data = decode_var_data(&var_data);

    println!("var_datav2: {decoded_data:?}");

    let td_report: tdx::TdReport = hcl_report.try_into().unwrap();
    let td_quote_bytes = imds::get_td_quote(&td_report).unwrap();
    let quote = QuoteV4::from_bytes(&td_quote_bytes);
    println!("QuoteV4v2: {quote:?}");
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HclVarData {
    pub keys: Vec<JwkKey>,
    #[serde(rename = "vm-configuration")]
    pub vm_configuration: VmConfiguration,
    #[serde(rename = "user-data")]
    pub user_data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwkKey {
    pub kid: String,
    pub key_ops: Vec<String>,
    pub kty: String,
    pub e: String,
    pub n: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VmConfiguration {
    #[serde(rename = "console-enabled")]
    pub console_enabled: bool,
    #[serde(rename = "root-cert-thumbprint")]
    pub root_cert_thumbprint: String,
    #[serde(rename = "secure-boot")]
    pub secure_boot: bool,
    #[serde(rename = "tpm-enabled")]
    pub tpm_enabled: bool,
    #[serde(rename = "tpm-persisted")]
    pub tpm_persisted: bool,
    #[serde(rename = "vmUniqueId")]
    pub vm_unique_id: String,
}

pub fn decode_var_data(var_data: &[u8]) -> HclVarData {
    // Convert bytes to UTF-8 string
    let json_str = std::str::from_utf8(var_data).unwrap();

    // Parse JSON into struct
    let hcl_data: HclVarData = serde_json::from_str(json_str).unwrap();

    hcl_data
}