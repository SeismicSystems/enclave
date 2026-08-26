//! Seismic attestation policy wrapper.
//!
//! Low-level quote, Azure HCL, vTPM, AK-certificate-chain, DCAP verification,
//! and measurement-policy matching are delegated to the Flashbots `attestation`
//! backend. This crate should stay thin: it owns Seismic protocol bindings,
//! safe policy constructors, and typed verified outputs for Seismic callers.
//!
//! # Main entry points
//!
//! Production callers usually only need these APIs. The two verification
//! flavors serve different callers, split by what the caller's trust anchor
//! is:
//!
//! - [`generate_evidence`] to produce local attestation evidence for a
//!   caller-supplied 64-byte protocol binding (see [`bindings`]).
//! - [`verify_evidence_with_policy`] to verify remote evidence against a
//!   [`SeismicMeasurementPolicy`]. For relying parties anchored to a
//!   measurement-policy document: clients/SDKs verifying the network's tx-io
//!   key advertisement, and operator tooling such as `verify-quote`.
//! - [`verify_evidence_with_predicate`] to verify remote evidence and appraise
//!   the verified measurements with a caller-supplied [`AdmissionPredicate`]
//!   (e.g. on-chain `MeasurementRegistry` membership). For nodes appraising
//!   the peer in the root-key bootstrap handshake, where what is admissible
//!   is a live decision owned by the caller, not a document.
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
/// The backend error enum [`AttestationError::Backend`] wraps, and the two
/// nested enums a caller has to descend into to tell a verdict on the evidence
/// apart from its own collateral infrastructure failing: the Azure verifier
/// funnels every Azure TDX outcome through `MaaError`, and the DCAP layer
/// reports a collateral-cache failure as `DcapVerificationError::Pccs`.
pub use attestation::{
    AttestationError as BackendAttestationError, azure::MaaError, dcap::DcapVerificationError,
};
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
///
/// For relying parties whose trust anchor is a measurement-policy document
/// (e.g. seismic-images' `build/measurements.json`): TxSeismic clients
/// verifying the network's tx-io key advertisement, and operator tooling.
/// Nodes appraising the peer in the root-key bootstrap handshake use
/// [`verify_evidence_with_predicate`] instead.
pub async fn verify_evidence_with_policy(
    evidence: AttestationExchangeMessage,
    expected_binding: [u8; 64],
    policy: SeismicMeasurementPolicy,
    options: VerifyOptions,
) -> Result<VerifiedSeismicAttestation, AttestationError> {
    verify_with_backend_policy(
        evidence,
        expected_binding,
        policy.into_backend_policy(),
        options,
    )
    .await
}

/// Verify remote attestation evidence with the backend and appraise the
/// resulting typed measurements with `admission`.
///
/// For nodes appraising the peer in the root-key bootstrap handshake, where
/// admissibility is a live decision the caller owns (e.g. on-chain
/// `MeasurementRegistry` membership) rather than a policy document. Relying
/// parties that hold a policy document use [`verify_evidence_with_policy`]
/// instead.
///
/// Verification and admission are one operation: the backend performs full
/// cryptographic verification (quote chain, freshness, binding) for the
/// evidence's attestation type, and the predicate then decides whether the
/// verified guest is admitted. Evidence whose measurements the predicate
/// denies fails with [`AttestationError::AdmissionDenied`]; there is no way to
/// obtain the verified output without the predicate passing.
pub async fn verify_evidence_with_predicate(
    evidence: AttestationExchangeMessage,
    expected_binding: [u8; 64],
    admission: &impl AdmissionPredicate,
) -> Result<VerifiedSeismicAttestation, AttestationError> {
    // Backend appraisal pinned to the evidence's own attestation type is
    // cryptographic verification only — admissibility (including which
    // attestation types are acceptable at all) is the predicate's job.
    let crypto_only =
        BackendMeasurementPolicy::single_attestation_type(evidence.attestation_type());
    let verified = verify_with_backend_policy(
        evidence,
        expected_binding,
        crypto_only,
        VerifyOptions::default(),
    )
    .await?;

    admission
        .admit(&verified)
        .await
        .map_err(AttestationError::AdmissionDenied)?;
    Ok(verified)
}

async fn verify_with_backend_policy(
    evidence: AttestationExchangeMessage,
    expected_binding: [u8; 64],
    backend_policy: BackendMeasurementPolicy,
    options: VerifyOptions,
) -> Result<VerifiedSeismicAttestation, AttestationError> {
    let attestation_type = evidence.attestation_type();
    let verifier = AttestationVerifier::new(
        backend_policy,
        options.pccs_url,
        options.dump_dcap_quotes,
        options.override_azure_outdated_tcb,
    );

    let measurements = verifier
        .verify_attestation(evidence, expected_binding)
        .await?
        // The verifier accepts evidence that declares no attestation when its
        // policy names no attested platform, and reports that as `None`. Every
        // Seismic relying party appraises a TEE node, so unattested evidence is
        // refused here, before any admission predicate sees it.
        .ok_or(AttestationError::Unattested)?;

    VerifiedSeismicAttestation::from_backend(attestation_type, expected_binding, measurements)
}

// === Public policy and output types ===

/// Admission appraisal applied to typed verified measurements, the second
/// phase of [`verify_evidence_with_predicate`].
///
/// Cryptographic verification establishes *which* guest produced the evidence
/// (its verified measurements); an admission predicate decides whether that
/// guest is *allowed* — for example, membership of its derived admission ID in
/// the on-chain `MeasurementRegistry`. Predicates own the entire appraisal,
/// including which attestation types they admit: a predicate must deny
/// [`VerifiedSeismicAttestation`] variants it does not appraise.
pub trait AdmissionPredicate {
    /// Appraise verified measurements; any `Err` denies admission.
    fn admit(
        &self,
        verified: &VerifiedSeismicAttestation,
    ) -> impl Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send;
}

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
/// Every variant carries verified measurements from an attested platform.
/// Provider-specific measurements stay in provider-specific variants so
/// callers cannot accidentally combine, for example, `dcap-tdx` with Azure
/// PCRs.
///
/// The variants mirror the verifier's [`MultiMeasurements`] paired with the
/// [`AttestationType`] that produced them; `from_backend` is the one place
/// the two are matched up, and a platform not mirrored here fails there as
/// [`AttestationError::MeasurementTypeMismatch`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifiedSeismicAttestation {
    AzureTdx(VerifiedAzureAttestation),
    DcapTdx(VerifiedTdxAttestation),
    GcpTdx(VerifiedTdxAttestation),
}

impl VerifiedSeismicAttestation {
    fn from_backend(
        attestation_type: AttestationType,
        binding: [u8; 64],
        measurements: MultiMeasurements,
    ) -> Result<Self, AttestationError> {
        match (attestation_type, measurements) {
            (AttestationType::AzureTdx, MultiMeasurements::Azure(pcrs)) => {
                Ok(Self::AzureTdx(VerifiedAzureAttestation {
                    binding,
                    guest_measurements: AzureGuestMeasurements {
                        pcrs: pcrs.into_iter().collect(),
                    },
                }))
            }
            (AttestationType::DcapTdx, MultiMeasurements::Dcap(measurements)) => {
                Ok(Self::DcapTdx(VerifiedTdxAttestation {
                    binding,
                    measurements: measurements.into(),
                }))
            }
            (AttestationType::GcpTdx, MultiMeasurements::Dcap(measurements)) => {
                Ok(Self::GcpTdx(VerifiedTdxAttestation {
                    binding,
                    measurements: measurements.into(),
                }))
            }
            (attestation_type, measurements) => Err(AttestationError::MeasurementTypeMismatch {
                attestation_type,
                measurements: Box::new(measurements),
            }),
        }
    }

    pub fn attestation_type(&self) -> AttestationType {
        match self {
            Self::AzureTdx(_) => AttestationType::AzureTdx,
            Self::DcapTdx(_) => AttestationType::DcapTdx,
            Self::GcpTdx(_) => AttestationType::GcpTdx,
        }
    }

    pub fn binding(&self) -> &[u8; 64] {
        match self {
            Self::AzureTdx(verified) => &verified.binding,
            Self::DcapTdx(verified) | Self::GcpTdx(verified) => &verified.binding,
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
    #[error("verified measurements denied admission: {0}")]
    AdmissionDenied(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("measurement policy format error: {0}")]
    PolicyFormat(#[from] MeasurementFormatError),
    #[error("evidence declares no attestation; only attested evidence is verified")]
    Unattested,
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
            MultiMeasurements::Azure(HashMap::from([(4, pcr4)])),
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
            MultiMeasurements::Dcap(attestation::measurements::DcapMeasurements::new(
                mrtd, [0u8; 48], [1u8; 48], [2u8; 48], [3u8; 48],
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

    /// A peer that declares no attestation gets a backend policy for `none`,
    /// which the backend accepts; the refusal has to be this crate's.
    #[tokio::test]
    async fn unattested_evidence_is_refused_before_admission() {
        struct AdmitEverything;
        impl AdmissionPredicate for AdmitEverything {
            async fn admit(
                &self,
                _verified: &VerifiedSeismicAttestation,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Ok(())
            }
        }

        let result = verify_evidence_with_predicate(
            AttestationExchangeMessage::without_attestation(),
            [0u8; 64],
            &AdmitEverything,
        )
        .await;

        assert!(matches!(result, Err(AttestationError::Unattested)));
    }

    #[test]
    fn rejects_measurements_inconsistent_with_attestation_type() {
        let result = VerifiedSeismicAttestation::from_backend(
            AttestationType::AzureTdx,
            [9u8; 64],
            MultiMeasurements::NoAttestation,
        );

        assert!(matches!(
            result,
            Err(AttestationError::MeasurementTypeMismatch {
                attestation_type: AttestationType::AzureTdx,
                ..
            })
        ));
    }
}
