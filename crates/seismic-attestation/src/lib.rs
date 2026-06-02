//! Seismic attestation policy helpers.
//!
//! This crate intentionally does not implement DCAP cryptography. It owns the
//! Seismic-specific semantics around evidence envelopes, protocol bindings,
//! measurements, and provider-specific binding checks. The underlying QVL can be
//! swapped later behind this crate's public types.

use az_cvm_vtpm::hcl::{HclReport, ReportType};
use dcap_rs::types::quotes::{body::QuoteBody, version_4::QuoteV4};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::panic::{AssertUnwindSafe, catch_unwind};
use thiserror::Error;

/// Current Azure TDX evidence envelope produced by `seismic-enclave-server`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AzureTdxEvidence {
    /// Azure HCL/vTPM attestation report bytes.
    ///
    /// Microsoft documents this as the Azure-defined attestation report read
    /// from TPM NV index `0x01400001`. It contains a header, the hardware
    /// report payload, and runtime data/claims. The hardware report's
    /// `report_data` captures the hash of the runtime claims, including
    /// `user-data` read from NV index `0x01400002`.
    ///
    /// See: https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design
    pub hcl_report: Vec<u8>,
    /// Raw Intel TDX DCAP quote bytes returned by Azure IMDS.
    pub quote: Vec<u8>,
}

/// Minimal verified quote fields needed by Seismic policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedQuoteFields {
    pub report_data: [u8; 64],
    pub measurements: TdxMeasurements,
}

/// TDX measurement identity surfaced to Seismic policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TdxMeasurements {
    pub mrtd: [u8; 48],
    pub mrseam: [u8; 48],
    pub rtmr0: [u8; 48],
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
    pub rtmr3: [u8; 48],
}

/// Static measurement policy for fixtures and initial deploy checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MeasurementPolicy {
    Any,
    Allowlist(Vec<TdxMeasurements>),
}

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("failed to parse Azure HCL report: {0}")]
    Hcl(#[from] az_cvm_vtpm::hcl::HclError),
    #[error("Azure HCL report is not a TDX report")]
    NotTdxHclReport,
    #[error("failed to parse HCL variable data JSON: {0}")]
    VarDataJson(#[from] serde_json::Error),
    #[error("HCL variable data is missing user-data")]
    MissingUserData,
    #[error("HCL user-data is not valid hex: {0}")]
    UserDataHex(#[from] hex::FromHexError),
    #[error("failed to parse DCAP quote")]
    QuoteParse,
    #[error("DCAP quote is not a TDX quote")]
    NotTdxQuote,
    #[error("Azure HCL variable-data hash does not match quote report_data")]
    AzureQuoteBindingMismatch,
    #[error("Seismic binding mismatch")]
    SeismicBindingMismatch,
    #[error("TDX measurements not allowed")]
    MeasurementMismatch,
}

// === Public API ===

/// Main entrypoint for verifying the Seismic policy around the current Azure
/// TDX evidence envelope.
///
/// This currently performs parsing/extraction and Seismic policy checks. Full
/// DCAP cryptographic verification is still done by the caller and will move
/// behind this API when we migrate to the chosen QVL.
pub fn verify_azure_tdx_policy(
    evidence: &AzureTdxEvidence,
    expected_binding: &[u8],
    measurement_policy: &MeasurementPolicy,
) -> Result<VerifiedQuoteFields, AttestationError> {
    let hcl_report = parse_azure_tdx_hcl_report(&evidence.hcl_report)?;
    let quote = parse_quote_v4(&evidence.quote)?;
    let quote_fields = extract_tdx_quote_fields(&quote)?;

    verify_azure_quote_binding(&hcl_report, &quote_fields.report_data)?;
    verify_azure_user_data(&hcl_report, expected_binding)?;
    verify_measurements(&quote_fields.measurements, measurement_policy)?;

    Ok(quote_fields)
}

/// Binding for TxSeismic tx_io public key evidence.
pub fn tx_io_binding(tx_io_pk: &[u8], epoch: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"seismic-tx-io:");
    hasher.update(tx_io_pk);
    hasher.update(epoch.to_be_bytes());
    hasher.finalize().into()
}

/// Binding for a root-key bootstrap requester quote.
pub fn root_key_request_binding(nonce_b: &[u8], eph_pk_b: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(nonce_b);
    hasher.update(eph_pk_b);
    hasher.finalize().into()
}

/// Binding for a root-key bootstrap responder quote.
pub fn root_key_response_binding(nonce_b: &[u8], eph_pk_a: &[u8], wrapped: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(nonce_b);
    hasher.update(eph_pk_a);
    hasher.update(wrapped);
    hasher.finalize().into()
}

// === Internal helpers ===

#[derive(Deserialize)]
struct HclVarDataUserData {
    #[serde(rename = "user-data")]
    user_data: Option<String>,
}

/// Parse the Azure HCL report and ensure it wraps a TDX report.
fn parse_azure_tdx_hcl_report(bytes: &[u8]) -> Result<HclReport, AttestationError> {
    let hcl_report = HclReport::new(bytes.to_vec())?;
    if hcl_report.report_type() != ReportType::Tdx {
        return Err(AttestationError::NotTdxHclReport);
    }
    Ok(hcl_report)
}

/// Extract the caller-supplied Azure HCL `user-data` bytes.
fn extract_azure_user_data(hcl_report: &HclReport) -> Result<Vec<u8>, AttestationError> {
    let var_data: HclVarDataUserData = serde_json::from_slice(hcl_report.var_data())?;
    let user_data = var_data
        .user_data
        .ok_or(AttestationError::MissingUserData)?;
    Ok(hex::decode(user_data.trim_start_matches("0x"))?)
}

/// Compute the hash Azure places in the TD report / quote report_data prefix.
fn azure_var_data_hash(hcl_report: &HclReport) -> [u8; 32] {
    hcl_report.var_data_sha256()
}

/// Verify that the raw DCAP quote is bound to the Azure HCL variable data.
fn verify_azure_quote_binding(
    hcl_report: &HclReport,
    quote_report_data: &[u8; 64],
) -> Result<(), AttestationError> {
    let expected = azure_var_data_hash(hcl_report);
    if quote_report_data[..32] != expected {
        return Err(AttestationError::AzureQuoteBindingMismatch);
    }
    Ok(())
}

/// Verify that the Azure HCL user-data equals the Seismic protocol binding.
fn verify_azure_user_data(
    hcl_report: &HclReport,
    expected_binding: &[u8],
) -> Result<(), AttestationError> {
    let user_data = extract_azure_user_data(hcl_report)?;
    if user_data != expected_binding {
        return Err(AttestationError::SeismicBindingMismatch);
    }
    Ok(())
}

/// Panic-safe parse of the current `dcap-rs` QuoteV4 type.
fn parse_quote_v4(bytes: &[u8]) -> Result<QuoteV4, AttestationError> {
    // `dcap-rs` 0.1.0 indexes into the input directly and panics on short
    // buffers. Avoid invoking it for obviously invalid data so tests and CLI
    // callers don't emit panic noise even though `catch_unwind` would recover.
    if bytes.len() < 48 {
        return Err(AttestationError::QuoteParse);
    }

    catch_unwind(AssertUnwindSafe(|| QuoteV4::from_bytes(bytes)))
        .map_err(|_| AttestationError::QuoteParse)
}

/// Extract TDX report data and measurements from a parsed quote.
fn extract_tdx_quote_fields(quote: &QuoteV4) -> Result<VerifiedQuoteFields, AttestationError> {
    let QuoteBody::TD10QuoteBody(body) = quote.quote_body else {
        return Err(AttestationError::NotTdxQuote);
    };

    Ok(VerifiedQuoteFields {
        report_data: body.report_data,
        measurements: TdxMeasurements {
            mrtd: body.mrtd,
            mrseam: body.mrseam,
            rtmr0: body.rtmr0,
            rtmr1: body.rtmr1,
            rtmr2: body.rtmr2,
            rtmr3: body.rtmr3,
        },
    })
}

fn verify_measurements(
    measurements: &TdxMeasurements,
    policy: &MeasurementPolicy,
) -> Result<(), AttestationError> {
    match policy {
        MeasurementPolicy::Any => Ok(()),
        MeasurementPolicy::Allowlist(allowed) if allowed.iter().any(|m| m == measurements) => {
            Ok(())
        }
        MeasurementPolicy::Allowlist(_) => Err(AttestationError::MeasurementMismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_helpers_are_stable() {
        assert_eq!(
            hex::encode(tx_io_binding(b"pk", 7)),
            "0cf7d05bc0019123fdf7a69cb91ad265625f9673172508b4f682e3d917b0f11c"
        );
        assert_eq!(
            hex::encode(root_key_request_binding(b"nonce", b"pk_b")),
            "3375ae192a636e95828a472e73d218576813c66fb67bd42f123f810c1953ca6d"
        );
        assert_eq!(
            hex::encode(root_key_response_binding(b"nonce", b"pk_a", b"wrapped")),
            "d2ac32239b55995fb355fc426dc0876d629d00abdcf244359dee2c0f2b6c2681"
        );
    }

    #[test]
    fn measurement_policy_allowlist() {
        let measurements = TdxMeasurements {
            mrtd: [1; 48],
            mrseam: [2; 48],
            rtmr0: [3; 48],
            rtmr1: [4; 48],
            rtmr2: [5; 48],
            rtmr3: [6; 48],
        };

        assert!(verify_measurements(&measurements, &MeasurementPolicy::Any).is_ok());
        assert!(
            verify_measurements(
                &measurements,
                &MeasurementPolicy::Allowlist(vec![measurements.clone()])
            )
            .is_ok()
        );
        assert!(verify_measurements(&measurements, &MeasurementPolicy::Allowlist(vec![])).is_err());
    }

    #[test]
    fn quote_parse_error_is_structured() {
        assert!(matches!(
            parse_quote_v4(b"not a quote"),
            Err(AttestationError::QuoteParse)
        ));
    }
}
