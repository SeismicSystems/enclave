//! Seismic attestation policy helpers.
//!
//! This crate intentionally does not implement DCAP cryptography. It owns the
//! Seismic-specific semantics around evidence envelopes, protocol bindings,
//! measurements, and provider-specific binding checks. The underlying QVL can be
//! swapped later behind this crate's public types.
//!
//! Azure caveat: Azure CVMs run the guest under Microsoft OpenHCL/OpenVMM
//! paravisor/nested virtualization. The raw TDX quote measurements surfaced here
//! are therefore platform/paravisor measurements, not sufficient Seismic guest OS
//! identity. Azure production policy also needs vTPM PCR quote/event-log (or MAA
//! JWT claim) verification before treating an enclave as running the expected
//! Seismic image.

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
///
/// On Azure these fields describe the paravisor-backed TDX platform evidence.
/// They must not be used as the only guest image measurement policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedQuoteFields {
    pub report_data: [u8; 64],
    pub measurements: TdxMeasurements,
}

/// TDX platform/paravisor measurements surfaced to Seismic policy.
///
/// TODO(attestation): split this into `TdxPlatformMeasurements` and add an
/// Azure `GuestMeasurements`/PCR policy type. The old name is kept temporarily
/// to avoid churn while callers migrate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TdxMeasurements {
    pub mrtd: [u8; 48],
    pub mrseam: [u8; 48],
    pub rtmr0: [u8; 48],
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
    pub rtmr3: [u8; 48],
}

/// Static TDX platform measurement policy for fixtures.
///
/// On Azure this is not sufficient for production guest allowlisting; use vTPM
/// PCR/event-log or MAA claims once those evidence types are added.
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
    #[error("Seismic binding is too long for Azure user-data: {len} bytes > 64")]
    BindingTooLong { len: usize },
    #[error("TDX measurements not allowed")]
    MeasurementMismatch,
}

// === Public API ===

/// Main entrypoint for checking bindings around the current Azure HCL + TDX
/// evidence envelope.
///
/// This currently performs parsing/extraction and Seismic policy checks. Full
/// DCAP cryptographic verification is still done by the caller and will move
/// behind this API when we migrate to the chosen QVL.
///
/// Azure caveat: this does not verify guest PCRs/event logs or an MAA JWT. A
/// successful result is not by itself proof of the Seismic guest OS image.
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
    if user_data == expected_binding || user_data == azure_user_data_for_binding(expected_binding)?
    {
        return Ok(());
    }
    Err(AttestationError::SeismicBindingMismatch)
}

fn azure_user_data_for_binding(binding: &[u8]) -> Result<Vec<u8>, AttestationError> {
    if binding.len() > 64 {
        return Err(AttestationError::BindingTooLong { len: binding.len() });
    }

    let mut user_data = binding.to_vec();
    if user_data.len() < 64 {
        user_data.resize(64, 0);
    }
    Ok(user_data)
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
    fn azure_user_data_binding_allows_zero_padding() {
        let binding = [1u8; 32];
        let mut padded = binding.to_vec();
        padded.resize(64, 0);

        assert_eq!(azure_user_data_for_binding(&binding).unwrap(), padded);
        assert_eq!(azure_user_data_for_binding(&padded).unwrap(), padded);
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
    fn azure_tdx_fixture_verifies_policy() {
        let fixture = AzureFixture::load();
        let evidence = AzureTdxEvidence {
            hcl_report: fixture.hcl_report.clone(),
            quote: fixture.quote.clone(),
        };

        let verified =
            verify_azure_tdx_policy(&evidence, &fixture.binding, &MeasurementPolicy::Any).unwrap();

        assert_eq!(verified.report_data, fixture.quote_report_data);
    }

    #[test]
    fn azure_tdx_fixture_rejects_wrong_binding() {
        let fixture = AzureFixture::load();
        let evidence = AzureTdxEvidence {
            hcl_report: fixture.hcl_report,
            quote: fixture.quote,
        };
        let wrong_binding = [0xff; 32];

        assert!(matches!(
            verify_azure_tdx_policy(&evidence, &wrong_binding, &MeasurementPolicy::Any,),
            Err(AttestationError::SeismicBindingMismatch)
        ));
    }

    #[test]
    fn azure_tdx_fixture_rejects_wrong_measurement() {
        let fixture = AzureFixture::load();
        let evidence = AzureTdxEvidence {
            hcl_report: fixture.hcl_report,
            quote: fixture.quote,
        };
        let wrong_measurement = TdxMeasurements {
            mrtd: [0xff; 48],
            mrseam: [0xff; 48],
            rtmr0: [0xff; 48],
            rtmr1: [0xff; 48],
            rtmr2: [0xff; 48],
            rtmr3: [0xff; 48],
        };

        assert!(matches!(
            verify_azure_tdx_policy(
                &evidence,
                &fixture.binding,
                &MeasurementPolicy::Allowlist(vec![wrong_measurement]),
            ),
            Err(AttestationError::MeasurementMismatch)
        ));
    }

    #[test]
    fn quote_parse_error_is_structured() {
        assert!(matches!(
            parse_quote_v4(b"not a quote"),
            Err(AttestationError::QuoteParse)
        ));
    }

    struct AzureFixture {
        binding: Vec<u8>,
        hcl_report: Vec<u8>,
        quote: Vec<u8>,
        quote_report_data: [u8; 64],
    }

    impl AzureFixture {
        fn load() -> Self {
            let fixture: serde_json::Value =
                serde_json::from_str(include_str!("../fixtures/azure-tdx-v1.json")).unwrap();

            Self {
                binding: decode_fixture_hex(&fixture, "binding_hex"),
                hcl_report: decode_fixture_hex(&fixture, "hcl_report_hex"),
                quote: decode_fixture_hex(&fixture, "quote_hex"),
                quote_report_data: decode_fixture_hex(&fixture, "quote_report_data_hex")
                    .try_into()
                    .unwrap(),
            }
        }
    }

    fn decode_fixture_hex(fixture: &serde_json::Value, key: &str) -> Vec<u8> {
        hex::decode(fixture[key].as_str().unwrap()).unwrap()
    }
}
