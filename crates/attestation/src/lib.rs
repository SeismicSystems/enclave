//! Seismic attestation policy wrapper.
//!
//! Low-level quote, Azure HCL, vTPM, AK-certificate-chain, DCAP verification,
//! and measurement-policy matching are delegated to the Flashbots `attestation`
//! backend. This crate should stay thin: it owns Seismic protocol bindings,
//! safe policy constructors, and typed verified outputs for Seismic callers.
//!
//! # Main entry points
//!
//! Production callers usually only need these APIs:
//!
//! - [`generate_evidence`] to produce local attestation evidence for a
//!   caller-supplied 64-byte protocol binding (see [`bindings`]).
//! - [`verify_evidence`] to verify remote evidence against a
//!   [`SeismicMeasurementPolicy`].
//! - [`SeismicMeasurementPolicy::from_json_bytes`] or
//!   [`SeismicMeasurementPolicy::from_file`] to load measurement policies,
//!   such as seismic-images' `build/measurements.json`.

pub mod bindings;

/// Manifest schema and `network_id` derivation, re-exported from the
/// dependency-light `seismic-network-manifest` crate so node-side callers
/// keep one import path.
pub use seismic_network_manifest as manifest;
pub use seismic_network_manifest::{ManifestError, NetworkId, NetworkManifestV1};

/// Backend measurement types returned after successful verification.
pub use attestation::measurements::{DcapMeasurementRegister, MultiMeasurements};
/// Backend evidence envelope and attestation-type enum used on the wire.
pub use attestation::{AttestationExchangeMessage, AttestationType};

use attestation::{
    AttestationGenerator, AttestationVerifier,
    measurements::{MeasurementFormatError, MeasurementPolicy as BackendMeasurementPolicy},
};
use std::{collections::HashMap, path::PathBuf};
use thiserror::Error;

// === Main public entrypoints ===

/// Generate local attestation evidence bound to `binding`.
///
/// This is generic over the backend [`AttestationType`] and delegates evidence
/// creation directly to Flashbots `attestation`.
///
/// Operational note (AzureTdx): the backend opens the raw TPM device
/// (`/dev/tpm0`, exclusive-open) and binds `binding` through the vTPM's
/// shared report-data NV index — a write, a fixed 3-second wait, and an IMDS
/// round-trip per call. Each call therefore costs seconds, and evidence
/// generation must be serialized machine-wide: a concurrent TPM client fails
/// the device open, and a concurrent report-data writer yields a report that
/// fails verification. Upstream RFEs: TCTI configurability
/// ([azure-cvm-tooling#92], [attested-tls#72]) and report-readiness polling
/// ([azure-cvm-tooling#93], [attested-tls#73]).
///
/// [azure-cvm-tooling#92]: https://github.com/kinvolk/azure-cvm-tooling/issues/92
/// [azure-cvm-tooling#93]: https://github.com/kinvolk/azure-cvm-tooling/issues/93
/// [attested-tls#72]: https://github.com/flashbots/attested-tls/issues/72
/// [attested-tls#73]: https://github.com/flashbots/attested-tls/issues/73
pub fn generate_evidence(
    attestation_type: AttestationType,
    binding: [u8; 64],
) -> Result<AttestationExchangeMessage, AttestationError> {
    let generator = AttestationGenerator::new(attestation_type, None)?;
    Ok(generator.generate_attestation(binding)?)
}

/// Verify remote attestation evidence with the backend, enforce the supplied
/// measurement policy, and return typed Seismic output.
pub async fn verify_evidence(
    evidence: AttestationExchangeMessage,
    expected_binding: [u8; 64],
    policy: SeismicMeasurementPolicy,
) -> Result<VerifiedSeismicAttestation, AttestationError> {
    verify_evidence_with_options(evidence, expected_binding, policy, VerifyOptions::default()).await
}

/// Same as [`verify_evidence`], with backend operational options.
pub async fn verify_evidence_with_options(
    evidence: AttestationExchangeMessage,
    expected_binding: [u8; 64],
    policy: SeismicMeasurementPolicy,
    options: VerifyOptions,
) -> Result<VerifiedSeismicAttestation, AttestationError> {
    let attestation_type = evidence.attestation_type();
    let verifier = AttestationVerifier::new(
        policy.into_backend_policy(),
        options.pccs_url,
        options.dump_dcap_quotes,
        options.override_azure_outdated_tcb,
    );

    let measurements = verifier
        .verify_attestation(evidence, expected_binding)
        .await?;

    VerifiedSeismicAttestation::from_backend(attestation_type, expected_binding, measurements)
}

/// Generate local Azure TDX + vTPM evidence bound to `binding`.
///
/// Convenience wrapper around [`generate_evidence`] for the backend Seismic uses
/// today.
pub fn generate_azure_evidence(
    binding: [u8; 64],
) -> Result<AttestationExchangeMessage, AttestationError> {
    generate_evidence(AttestationType::AzureTdx, binding)
}

/// Verify remote Azure TDX + vTPM evidence and return typed Azure output.
///
/// Measurement parsing and matching still use the backend policy format; this
/// function only checks that the verified result is Azure and unwraps it for
/// Azure-specific callers.
pub async fn verify_azure_evidence(
    evidence: AttestationExchangeMessage,
    expected_binding: [u8; 64],
    policy: SeismicMeasurementPolicy,
) -> Result<VerifiedAzureAttestation, AttestationError> {
    verify_azure_evidence_with_options(evidence, expected_binding, policy, VerifyOptions::default())
        .await
}

/// Same as [`verify_azure_evidence`], with backend operational options.
pub async fn verify_azure_evidence_with_options(
    evidence: AttestationExchangeMessage,
    expected_binding: [u8; 64],
    policy: SeismicMeasurementPolicy,
    options: VerifyOptions,
) -> Result<VerifiedAzureAttestation, AttestationError> {
    if evidence.attestation_type() != AttestationType::AzureTdx {
        return Err(AttestationError::WrongAttestationType {
            expected: AttestationType::AzureTdx,
            actual: evidence.attestation_type(),
        });
    }

    match verify_evidence_with_options(evidence, expected_binding, policy, options).await? {
        VerifiedSeismicAttestation::AzureTdx(verified) => Ok(verified),
        verified => Err(AttestationError::WrongAttestationType {
            expected: AttestationType::AzureTdx,
            actual: verified.attestation_type(),
        }),
    }
}

// === Public policy and output types ===

/// Seismic-safe wrapper around the attestation backend's measurement policy.
///
/// The underlying JSON/file format is the backend's format. This wrapper exists
/// to keep production constructors explicit and to avoid spreading backend
/// operational choices throughout Seismic services.
#[derive(Clone, Debug)]
pub struct SeismicMeasurementPolicy {
    backend_policy: BackendMeasurementPolicy,
}

impl SeismicMeasurementPolicy {
    /// Parse a measurement policy JSON document.
    ///
    /// This is the expected path for seismic-images' `build/measurements.json`
    /// (the `make measure` output).
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, AttestationError> {
        Ok(Self {
            backend_policy: BackendMeasurementPolicy::from_json_bytes(bytes.to_vec())?,
        })
    }

    /// Load a measurement policy from a file.
    pub async fn from_file(path: impl Into<PathBuf>) -> Result<Self, AttestationError> {
        Ok(Self {
            backend_policy: BackendMeasurementPolicy::from_file(path.into()).await?,
        })
    }

    /// Intentionally accept any measurements for one attestation type after
    /// backend cryptographic verification succeeds.
    ///
    /// This is useful for local debugging and measurement capture before a
    /// measurements file exists. Do not use it in production authorization
    /// paths.
    pub fn dangerously_accept_any_for_testing(attestation_type: AttestationType) -> Self {
        Self {
            backend_policy: BackendMeasurementPolicy::single_attestation_type(attestation_type),
        }
    }

    fn into_backend_policy(self) -> BackendMeasurementPolicy {
        self.backend_policy
    }
}

/// Operational options passed through to the attestation backend verifier.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifyOptions {
    /// Optional PCCS URL for DCAP collateral. If omitted, the backend default is used.
    pub pccs_url: Option<String>,
    /// Ask the backend to log/dump DCAP quote material for debugging.
    pub dump_dcap_quotes: bool,
    /// Allow the backend's Azure outdated-TCB override path.
    pub override_azure_outdated_tcb: bool,
}

/// Generic verified Seismic attestation output.
///
/// Provider-specific measurements stay in provider-specific variants so callers
/// cannot accidentally combine, for example, `dcap-tdx` with Azure PCRs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifiedSeismicAttestation {
    AzureTdx(VerifiedAzureAttestation),
    DcapTdx(VerifiedTdxAttestation),
    GcpTdx(VerifiedTdxAttestation),
    NoAttestation { binding: [u8; 64] },
}

impl VerifiedSeismicAttestation {
    fn from_backend(
        attestation_type: AttestationType,
        binding: [u8; 64],
        measurements: Option<MultiMeasurements>,
    ) -> Result<Self, AttestationError> {
        match (attestation_type, measurements) {
            (AttestationType::None, None | Some(MultiMeasurements::NoAttestation)) => {
                Ok(Self::NoAttestation { binding })
            }
            (AttestationType::AzureTdx, Some(MultiMeasurements::Azure(pcrs))) => {
                Ok(Self::AzureTdx(VerifiedAzureAttestation {
                    binding,
                    guest_measurements: AzureGuestMeasurements {
                        pcrs: pcrs.into_iter().collect(),
                    },
                }))
            }
            (AttestationType::DcapTdx, Some(MultiMeasurements::Dcap(measurements))) => {
                Ok(Self::DcapTdx(VerifiedTdxAttestation {
                    binding,
                    measurements: measurements.into(),
                }))
            }
            (AttestationType::GcpTdx, Some(MultiMeasurements::Dcap(measurements))) => {
                Ok(Self::GcpTdx(VerifiedTdxAttestation {
                    binding,
                    measurements: measurements.into(),
                }))
            }
            (attestation_type, None) => {
                Err(AttestationError::MissingMeasurements { attestation_type })
            }
            (attestation_type, Some(measurements)) => {
                Err(AttestationError::MeasurementTypeMismatch {
                    attestation_type,
                    measurements: Box::new(measurements),
                })
            }
        }
    }

    pub fn attestation_type(&self) -> AttestationType {
        match self {
            Self::AzureTdx(_) => AttestationType::AzureTdx,
            Self::DcapTdx(_) => AttestationType::DcapTdx,
            Self::GcpTdx(_) => AttestationType::GcpTdx,
            Self::NoAttestation { .. } => AttestationType::None,
        }
    }

    pub fn binding(&self) -> &[u8; 64] {
        match self {
            Self::AzureTdx(verified) => &verified.binding,
            Self::DcapTdx(verified) | Self::GcpTdx(verified) => &verified.binding,
            Self::NoAttestation { binding } => binding,
        }
    }
}

/// Verified Azure TDX + vTPM identity consumed by higher-level Seismic services.
///
/// The measurements are Azure vTPM PCR state. They are not raw TDX
/// platform/paravisor MRTD/RTMR values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAzureAttestation {
    /// The 64-byte transcript/protocol binding verified by the backend.
    pub binding: [u8; 64],
    /// Backend-verified Azure guest measurements after backend policy matched.
    pub guest_measurements: AzureGuestMeasurements,
}

/// Azure guest measurements verified by the backend and checked by backend policy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AzureGuestMeasurements {
    pub pcrs: HashMap<u32, [u8; 32]>,
}

/// Verified TDX quote measurements for DCAP-like backends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedTdxAttestation {
    /// The 64-byte transcript/protocol binding verified by the backend.
    pub binding: [u8; 64],
    /// Backend-verified TDX measurements after backend policy matched.
    pub measurements: TdxMeasurements,
}

/// TDX measurements surfaced by DCAP/GCP backend attestation types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TdxMeasurements {
    pub mrtd: [u8; 48],
    pub rtmr0: [u8; 48],
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
    pub rtmr3: [u8; 48],
}

impl From<attestation::measurements::DcapMeasurements> for TdxMeasurements {
    fn from(measurements: attestation::measurements::DcapMeasurements) -> Self {
        Self {
            mrtd: measurements.mrtd,
            rtmr0: measurements.rtmr0,
            rtmr1: measurements.rtmr1,
            rtmr2: measurements.rtmr2,
            rtmr3: measurements.rtmr3,
        }
    }
}

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("attestation backend error: {0}")]
    Backend(#[from] attestation::AttestationError),
    #[error("measurement policy format error: {0}")]
    PolicyFormat(#[from] MeasurementFormatError),
    #[error("expected {expected} attestation, got {actual}")]
    WrongAttestationType {
        expected: AttestationType,
        actual: AttestationType,
    },
    #[error("attestation backend returned no measurements for {attestation_type}")]
    MissingMeasurements { attestation_type: AttestationType },
    #[error("backend returned measurements inconsistent with {attestation_type}: {measurements:?}")]
    MeasurementTypeMismatch {
        attestation_type: AttestationType,
        measurements: Box<MultiMeasurements>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_policy_parses_flashbots_measurement_json_and_preserves_record_correlation() {
        let image_a_pcr4 = [0xA4u8; 32];
        let image_a_pcr9 = [0xA9u8; 32];
        let image_b_pcr4 = [0xB4u8; 32];
        let image_b_pcr9 = [0xB9u8; 32];
        let json = format!(
            r#"[
                {{
                    "measurement_id": "image-a",
                    "attestation_type": "azure-tdx",
                    "measurements": {{
                        "pcr4": {{ "expected": "{}" }},
                        "pcr9": {{ "expected": "{}" }}
                    }}
                }},
                {{
                    "measurement_id": "image-b",
                    "attestation_type": "azure-tdx",
                    "measurements": {{
                        "pcr4": {{ "expected": "{}" }},
                        "pcr9": {{ "expected": "{}" }}
                    }}
                }}
            ]"#,
            hex::encode(image_a_pcr4),
            hex::encode(image_a_pcr9),
            hex::encode(image_b_pcr4),
            hex::encode(image_b_pcr9),
        );
        let policy = SeismicMeasurementPolicy::from_json_bytes(json.as_bytes()).unwrap();

        let cross_product_measurements =
            MultiMeasurements::Azure(HashMap::from([(4, image_a_pcr4), (9, image_b_pcr9)]));
        assert!(
            policy
                .backend_policy
                .check_measurement(&cross_product_measurements, None)
                .is_err()
        );

        let image_b_measurements =
            MultiMeasurements::Azure(HashMap::from([(4, image_b_pcr4), (9, image_b_pcr9)]));
        policy
            .backend_policy
            .check_measurement(&image_b_measurements, None)
            .unwrap();
    }

    #[test]
    fn dangerous_accept_any_is_explicit() {
        let policy =
            SeismicMeasurementPolicy::dangerously_accept_any_for_testing(AttestationType::AzureTdx);

        policy
            .backend_policy
            .check_measurement(&MultiMeasurements::Azure(HashMap::new()), None)
            .unwrap();
        assert!(
            policy
                .backend_policy
                .check_measurement(&MultiMeasurements::NoAttestation, None)
                .is_err()
        );
    }

    #[test]
    fn converts_backend_azure_measurements_to_verified_output() {
        let binding = [3u8; 64];
        let pcr4 = [4u8; 32];
        let verified = VerifiedSeismicAttestation::from_backend(
            AttestationType::AzureTdx,
            binding,
            Some(MultiMeasurements::Azure(HashMap::from([(4, pcr4)]))),
        )
        .unwrap();

        assert_eq!(verified.attestation_type(), AttestationType::AzureTdx);
        assert_eq!(verified.binding(), &binding);
        match verified {
            VerifiedSeismicAttestation::AzureTdx(azure) => {
                assert_eq!(azure.guest_measurements.pcrs.get(&4), Some(&pcr4));
            }
            _ => panic!("expected Azure output"),
        }
    }

    #[test]
    fn converts_backend_dcap_measurements_to_verified_output() {
        let binding = [5u8; 64];
        let mrtd = [7u8; 48];
        let verified = VerifiedSeismicAttestation::from_backend(
            AttestationType::DcapTdx,
            binding,
            Some(MultiMeasurements::Dcap(
                attestation::measurements::DcapMeasurements::new(
                    mrtd, [0u8; 48], [1u8; 48], [2u8; 48], [3u8; 48],
                ),
            )),
        )
        .unwrap();

        assert_eq!(verified.attestation_type(), AttestationType::DcapTdx);
        assert_eq!(verified.binding(), &binding);
        match verified {
            VerifiedSeismicAttestation::DcapTdx(dcap) => {
                assert_eq!(
                    dcap.measurements,
                    TdxMeasurements {
                        mrtd,
                        rtmr0: [0u8; 48],
                        rtmr1: [1u8; 48],
                        rtmr2: [2u8; 48],
                        rtmr3: [3u8; 48],
                    }
                );
            }
            _ => panic!("expected DCAP output"),
        }
    }

    #[test]
    fn represents_verified_no_attestation() {
        let binding = [9u8; 64];
        let verified =
            VerifiedSeismicAttestation::from_backend(AttestationType::None, binding, None).unwrap();

        assert_eq!(verified.attestation_type(), AttestationType::None);
        assert_eq!(verified.binding(), &binding);
        assert_eq!(
            verified,
            VerifiedSeismicAttestation::NoAttestation { binding }
        );
    }
}
