use anyhow::{Context, Result, anyhow};
use dcap_rs::types::{collaterals::IntelCollateral, quotes::version_4::QuoteV4};
use x509_parser::pem::parse_x509_pem;

use crate::attestation::{CA, utils::get_pck_fmspc_and_issuer};

pub trait PccsProvider {
    fn new() -> Self;

    async fn get_collateral(&self, quote: &QuoteV4) -> Result<IntelCollateral>;

    async fn get_root_ca(&self) -> Result<(Vec<u8>, Vec<u8>)>;
    async fn get_tcb_info(
        &self,
        tcb_type: u8,
        fmspc: &str,
        version: u32,
    ) -> Result<(Vec<u8>, Vec<u8>)>;

    async fn get_enclave_identity(&self, version: u32) -> Result<Vec<u8>>;

    async fn get_certificate_by_id(&self, ca_id: CA) -> Result<(Vec<u8>, Vec<u8>)>;
}

pub struct IntelPccs {
    base_url: String,
    client: reqwest::Client,
}

impl PccsProvider for IntelPccs {
    fn new() -> Self {
        Self {
            base_url: "https://pccs.scrtlabs.com".to_string(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    async fn get_collateral(&self, quote: &QuoteV4) -> Result<IntelCollateral> {
        // 1. Get Root CA and root ca crl from PCCS
        let (root_ca, root_ca_crl) = self.get_root_ca().await?;

        if root_ca.is_empty() || root_ca_crl.is_empty() {
            return Err(anyhow!("Root CA or CRL is empty"));
        }

        // 2. get fmspc and pck_type from the quote cert
        let (fmspc, pck_type) = get_pck_fmspc_and_issuer(quote);

        // 3. get TCB info from PCCS

        // tcb_type: 0: SGX, 1: TDX
        // version: TDX uses TcbInfoV3
        let (tcb_info, signing_ca) = self.get_tcb_info(1, &fmspc, 4).await?;

        if signing_ca.is_empty() {
            return Err(anyhow!("Signing CA is empty".to_string()));
        }
        // 4. Get Enclave Identity from PCCS
        let quote_version = quote.header.version;
        let qe_identity = self.get_enclave_identity(quote_version as u32).await?;

        let (_, pck_crl) = self.get_certificate_by_id(pck_type).await?;
        if pck_crl.is_empty() {
            return Err(anyhow!("PCK CRL is empty".to_string()));
        }

        let mut collaterals = IntelCollateral::new();

        collaterals.set_tcbinfo_bytes(&tcb_info);
        collaterals.set_qeidentity_bytes(&qe_identity);
        collaterals.set_intel_root_ca_der(&root_ca);
        collaterals.set_sgx_tcb_signing_der(&signing_ca);
        collaterals.set_sgx_intel_root_ca_crl_der(&root_ca_crl);

        match pck_type {
            CA::PLATFORM => {
                collaterals.set_sgx_platform_crl_der(&pck_crl);
            }
            CA::PROCESSOR => {
                collaterals.set_sgx_processor_crl_der(&pck_crl);
            }
            _ => {
                return Err(anyhow!("Unknown PCK Type".to_string()));
            }
        }
        Ok(collaterals)
    }

    async fn get_root_ca(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let cert_url = "https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer";

        let cert_response = self
            .client
            .get(cert_url)
            .send()
            .await
            .context("Failed to fetch Root CA certificate")?;

        if !cert_response.status().is_success() {
            return Err(anyhow!(
                "Root CA certificate request failed with status {}: {}",
                cert_response.status(),
                cert_response.text().await.unwrap_or_default()
            ));
        }

        let cert = cert_response.bytes().await?.to_vec();

        // Fetch Root CA CRL
        let crl_url = format!("{}/sgx/certification/v4/rootcacrl", self.base_url);

        let crl_request = self.client.get(&crl_url);

        let crl_response = crl_request
            .send()
            .await
            .context("Failed to fetch Root CA CRL")?;

        if !crl_response.status().is_success() {
            return Err(anyhow!(
                "Root CA CRL request failed with status {}: {}",
                crl_response.status(),
                crl_response.text().await.unwrap_or_default()
            ));
        }
        let response_string = crl_response.text().await?;
        let crl = hex::decode(&response_string)?;

        Ok((cert, crl))
    }

    /// Get TCB Info for SGX or TDX
    ///
    /// # Arguments
    /// * `tcb_type` - 0 for SGX, 1 for TDX
    /// * `fmspc` - Hex-encoded FMSPC value (12 hex chars representing 6 bytes)
    /// * `version` - API version (should be 4 for v4 API)
    async fn get_tcb_info(
        &self,
        tcb_type: u8,
        fmspc: &str,
        version: u32,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let tech = match tcb_type {
            0 => "sgx",
            1 => "tdx",
            _ => return Err(anyhow!("Invalid tcb_type: must be 0 (SGX) or 1 (TDX)")),
        };

        let url = format!(
            "{}/{}/certification/v{}/tcb?fmspc={}",
            self.base_url, tech, version, fmspc
        );
        let request = self.client.get(&url);

        let response = request
            .send()
            .await
            .context("Failed to send TCB Info request")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "TCB Info request failed with status {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            ));
        }

        // Extract the certificate chain from headers
        let cert_chain_header = response
            .headers()
            .get("tcb-info-issuer-chain")
            .ok_or_else(|| anyhow!("Missing tcb-info-issuer-chain header"))?
            .to_str()
            .context("Invalid tcb-info-issuer-chain header encoding")?;

        // URL decode the certificate chain
        let decoded_chain = urlencoding::decode(cert_chain_header)
            .context("Failed to URL decode certificate chain")?;

        // Extract the first certificate (TCB Signing Certificate)
        let signing_cert_pem = extract_first_certificate(decoded_chain.as_bytes())?;

        // Convert PEM to DER
        let (_, pem) = parse_x509_pem(&signing_cert_pem)?;

        // Get the TCB Info JSON body
        let tcb_info_json = response.bytes().await?.to_vec();

        Ok((tcb_info_json, pem.contents))
    }

    /// Get Enclave Identity (QE Identity for SGX or TDX)
    ///
    /// # Arguments
    /// * `version` - API version (should be 4 for v4 API)
    async fn get_enclave_identity(&self, version: u32) -> Result<Vec<u8>> {
        // For TDX Quote verification, we typically need the TDX QE Identity
        let url = format!(
            "{}/tdx/certification/v{}/qe/identity",
            self.base_url, version
        );

        let request = self.client.get(&url);

        let response = request
            .send()
            .await
            .context("Failed to send QE Identity request")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "QE Identity request failed with status {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            ));
        }

        let qe_identity_json = response.bytes().await?.to_vec();

        Ok(qe_identity_json)
    }

    /// Get certificate by CA ID (Processor or Platform CA)
    /// Returns tuple of (certificate_chain, crl)
    ///
    /// # Arguments
    /// * `ca_id` - CA identifier (Processor or Platform)
    ///   Get certificate and CRL by CA ID (Root, Processor, or Platform CA)
    ///   Returns tuple of (certificate, crl)
    ///
    /// # Arguments
    /// * `ca_id` - CA identifier (Root, Processor or Platform)
    async fn get_certificate_by_id(&self, ca_id: CA) -> Result<(Vec<u8>, Vec<u8>)> {
        let ca_str = match ca_id {
            CA::PROCESSOR => "processor",
            CA::PLATFORM => "platform",
            _ => return Err(anyhow!("unssuported CA")),
        };

        // Get the CRL for this CA
        let crl_url = format!(
            "{}/sgx/certification/v4/pckcrl?ca={}",
            self.base_url, ca_str
        );

        let crl_request = self.client.get(&crl_url);

        let crl_response = crl_request
            .send()
            .await
            .context("Failed to send CRL request")?;

        if !crl_response.status().is_success() {
            return Err(anyhow!(
                "CRL request failed with status {}: {}",
                crl_response.status(),
                crl_response.text().await.unwrap_or_default()
            ));
        }

        // Extract the certificate chain from the response header
        let cert_chain = crl_response
            .headers()
            .get("SGX-PCK-CRL-Issuer-Chain")
            .ok_or_else(|| anyhow!("Missing SGX-PCK-CRL-Issuer-Chain header"))?
            .to_str()
            .context("Invalid certificate chain header")?;

        // URL decode the certificate chain
        let cert_chain = urlencoding::decode(cert_chain)
            .context("Failed to URL decode certificate chain")?
            .into_owned()
            .into_bytes();

        let response_string = crl_response.text().await?;
        let crl = hex::decode(response_string)?;

        // The cert chain contains both Root CA and the intermediate CA (Processor/Platform)
        // We need to parse and extract just the requested CA certificate
        // The chain format is: <Intermediate CA Cert><Root CA Cert>
        let cert = extract_first_certificate(&cert_chain)
            .context("Failed to extract CA certificate from chain")?;

        Ok((cert, crl))
    }
}

/// Extract the first certificate from a PEM certificate chain
fn extract_first_certificate(pem_chain: &[u8]) -> Result<Vec<u8>> {
    let chain_str =
        std::str::from_utf8(pem_chain).context("Certificate chain is not valid UTF-8")?;

    // Find the first certificate in the chain
    let begin_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";

    let start = chain_str
        .find(begin_marker)
        .ok_or_else(|| anyhow!("No certificate found in chain"))?;

    let end = chain_str[start..]
        .find(end_marker)
        .ok_or_else(|| anyhow!("Malformed certificate in chain"))?;

    // Extract the first certificate including the markers
    let cert = &chain_str[start..start + end + end_marker.len()];

    Ok(cert.as_bytes().to_vec())
}
