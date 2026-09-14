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
//!   key advertisement, and operator tooling (`seismic-verify-quote`, linked
//!   by the deploy CLI). It hands back the [`VerificationBundle`] the verdict
//!   rested on, for callers that archive the verification.
//! - [`verify_archived_evidence_with_policy`] to reproduce such a verdict
//!   later from its bundle, reaching no collateral service and depending in
//!   no way on when it runs.
//! - [`verify_evidence_with_predicate`] to verify remote evidence and appraise
//!   the verified measurements with a caller-supplied [`AdmissionPredicate`]
//!   (e.g. on-chain `MeasurementRegistry` membership). For nodes appraising
//!   the peer in the root-key bootstrap handshake, where what is admissible
//!   is a live decision owned by the caller, not a document.
//! - [`SeismicMeasurementPolicy::from_json_bytes`] or
//!   [`SeismicMeasurementPolicy::from_file`] to load measurement policies,
//!   such as seismic-images' `build/measurements.json`.
//!
//! # Re-verification
//!
//! A verdict is reproducible later only given everything the original
//! verification rested on:
//!
//! ```text
//! reproducible verdict = evidence
//!                      + everything the verifier fetched
//!                      + the instant every freshness check was evaluated at
//!                      + the trust anchors compiled into the verifying build
//! ```
//!
//! [`VerificationBundle`] is those four in one value, so a caller archives one
//! thing and a replay takes one thing. Two of them were never optional here
//! and are now stated once: the fetched material is the DCAP collateral
//! bundle, which the backend reports as optional because a platform may carry
//! its own endorsements, and which [`verify_evidence_with_policy`] requires
//! ([`AttestationError::NoFetchedDcapCollateral`]) because every platform a
//! Seismic relying party appraises has a fetched DCAP leg and nothing else
//! lets a founding be re-verified. The anchors cannot be archived as bytes
//! without freezing out a root rotation, so [`TrustAnchors`] records a
//! digest of each (and, for the one anchor the backend keeps unreachable,
//! the version of the crate carrying it): enough to notice that a replaying
//! build differs from the verifying one ([`TrustAnchors::drift_from`]),
//! without pinning.
//!
//! The relying party's own inputs, the binding it expects and the policy it
//! holds, are supplied again at replay. They are the claim being checked, not
//! provenance of the verification.

pub mod bindings;

/// Manifest schema and `network_id` derivation, re-exported from the
/// dependency-light `seismic-network-manifest` crate so node-side callers
/// keep one import path.
pub use seismic_network_manifest as manifest;
pub use seismic_network_manifest::{ManifestError, NetworkId, NetworkManifestV1};

/// The DCAP collateral bundle a verification fetched, as
/// [`VerificationBundle::dcap_collateral`] carries it.
pub use attestation::QuoteCollateralV3;
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
    AttestationGenerator, AttestationVerifier, EndorsementSnapshot,
    measurements::{MeasurementFormatError, MeasurementPolicy as BackendMeasurementPolicy},
};
use sha2::{Digest as _, Sha256};
use std::{collections::HashMap, fmt, path::PathBuf};
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
/// measurement policy, and return typed Seismic output beside the bundle the
/// verdict rested on.
///
/// For relying parties whose trust anchor is a measurement-policy document
/// (e.g. seismic-images' `build/measurements.json`): TxSeismic clients
/// verifying the network's tx-io key advertisement, and operator tooling.
/// Nodes appraising the peer in the root-key bootstrap handshake use
/// [`verify_evidence_with_predicate`] instead.
///
/// A live verification: the backend fetches the DCAP collateral the evidence
/// needs (from `options.pccs_url`, or its default provider) and holds every
/// freshness check to the wall clock. A caller that keeps the returned
/// [`VerificationBundle`] can reproduce this verdict later with
/// [`verify_archived_evidence_with_policy`].
pub async fn verify_evidence_with_policy(
    evidence: AttestationExchangeMessage,
    expected_binding: [u8; 64],
    policy: SeismicMeasurementPolicy,
    options: VerifyOptions,
) -> Result<VerifiedEvidence, AttestationError> {
    verify_with_backend_policy(
        evidence,
        expected_binding,
        policy.into_backend_policy(),
        options,
    )
    .await
}

/// Reproduce a verdict from the bundle a verification handed back, enforcing
/// the supplied measurement policy.
///
/// The evidence is checked against the bundle's own DCAP collateral, with
/// every freshness check evaluated at the bundle's instant rather than the
/// wall clock, and nothing is fetched: same bundle, same binding, same
/// policy, same verdict, however much later this runs. Intel's TCB Info, QE
/// Identity and both CRLs carry `nextUpdate` on a roughly 30-day cadence, so
/// this is the only way a verdict survives the month after it was reached.
///
/// Synchronous, since it awaits nothing. The one input it takes from this
/// build rather than the bundle is the compiled-in trust anchors; a caller
/// that wants to know whether they are the ones the verdict was reached under
/// compares `bundle.trust_anchors` with [`TrustAnchors::compiled_in`].
pub fn verify_archived_evidence_with_policy(
    bundle: &VerificationBundle,
    expected_binding: [u8; 64],
    policy: SeismicMeasurementPolicy,
) -> Result<VerifiedSeismicAttestation, AttestationError> {
    let attestation_type = bundle.evidence.attestation_type();
    // The verifier is built with a collateral source it never asks: the
    // archived path fetches nothing by construction.
    let verifier = backend_verifier(policy.into_backend_policy(), None, false);
    let endorsements =
        EndorsementSnapshot::dcap(bundle.dcap_collateral.clone(), bundle.verified_at);
    let verified = verifier
        .verify_attestation_archived(bundle.evidence.clone(), expected_binding, &endorsements)?
        .ok_or(AttestationError::Unattested)?;
    VerifiedSeismicAttestation::from_backend(
        attestation_type,
        expected_binding,
        verified.measurements,
    )
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
    .await?
    .attestation;

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
) -> Result<VerifiedEvidence, AttestationError> {
    let attestation_type = evidence.attestation_type();
    let verifier = backend_verifier(backend_policy, options.pccs_url, options.dump_dcap_quotes);

    let verified = verifier
        .verify_attestation(evidence.clone(), expected_binding)
        .await?
        // The verifier accepts evidence that declares no attestation when its
        // policy names no attested platform, and reports that as `None`. Every
        // Seismic relying party appraises a TEE node, so unattested evidence is
        // refused here, before any admission predicate sees it.
        .ok_or(AttestationError::Unattested)?;

    // The backend reports what it fetched as an `Option`: a platform may
    // carry its own endorsements, or have no DCAP leg at all. Every platform
    // a Seismic relying party appraises has a DCAP leg whose collateral is
    // fetched, and a founding archive cannot be replayed without it, so its
    // absence is a hard error here, once, and nothing below this line carries
    // the `Option`.
    let dcap_collateral = verified
        .endorsements
        .dcap
        .ok_or(AttestationError::NoFetchedDcapCollateral)?;

    Ok(VerifiedEvidence {
        attestation: VerifiedSeismicAttestation::from_backend(
            attestation_type,
            expected_binding,
            verified.measurements,
        )?,
        bundle: VerificationBundle {
            evidence,
            verified_at: verified.endorsements.at,
            dcap_collateral,
            trust_anchors: TrustAnchors::compiled_in(),
        },
    })
}

/// The backend verifier every Seismic verification runs through.
fn backend_verifier(
    backend_policy: BackendMeasurementPolicy,
    pccs_url: Option<String>,
    dump_dcap_quotes: bool,
) -> AttestationVerifier {
    let mut builder = AttestationVerifier::builder(backend_policy)
        .with_dump_dcap_quotes(dump_dcap_quotes)
        // The backend can rewrite one Azure FMSPC's TCB Info to clamp a
        // component's required SVN down, so a platform behind every published
        // TCB level matches one. No Seismic relying party asks for that: it
        // makes a verdict depend on a caller's flag rather than on the
        // evidence and the collateral, which is exactly what archived
        // founding evidence must not do.
        .with_override_azure_outdated_tcb(false);
    if let Some(url) = pccs_url {
        builder = builder.with_pccs_url(url);
    }
    // The default cache policy: every live verification fetches its own
    // collateral and no bundle is served from an in-process cache, so the
    // bundle a verification hands back is the one it consumed.
    builder.build()
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

/// Operational options for a live verification, passed through to the
/// attestation backend verifier.
///
/// The default fetches collateral from the backend's default provider and
/// holds every freshness check to the wall clock. An archived bundle is
/// replayed through [`verify_archived_evidence_with_policy`], which takes no
/// options: it reaches no collateral service at all.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifyOptions {
    /// Optional PCCS URL for DCAP collateral. If omitted, the backend default is used.
    pub pccs_url: Option<String>,
    /// Ask the backend to log/dump DCAP quote material for debugging.
    pub dump_dcap_quotes: bool,
}

/// A live verification's typed outcome, plus the bundle that reproduces it.
///
/// A caller archiving founding provenance keeps the bundle. Fetching its own
/// collateral instead does not substitute: a collateral cache may refresh
/// between two fetches, and a bundle without its instant does not re-verify.
#[derive(Clone, Debug)]
pub struct VerifiedEvidence {
    /// The verdict: what the evidence proved about the guest that produced it.
    pub attestation: VerifiedSeismicAttestation,
    /// Everything the verdict rested on that a replay has to be given.
    pub bundle: VerificationBundle,
}

/// Everything a verdict rested on, minus the relying party's own claim:
/// the evidence, what the verifier fetched, the instant it judged at, and the
/// trust anchors it judged with.
///
/// One value, so a caller archives one thing and a replay
/// ([`verify_archived_evidence_with_policy`]) takes one thing. The earlier
/// shape, the evidence in one place and a collateral snapshot in another,
/// left the pairing to the caller; two values that have to be kept together
/// are the shape of least resistance for filing one beside the wrong other.
///
/// The binding the evidence is expected to carry and the policy it is judged
/// against are not here: they are the relying party's inputs, supplied again
/// at replay.
#[derive(Clone, Debug)]
pub struct VerificationBundle {
    /// The evidence verified, verbatim.
    pub evidence: AttestationExchangeMessage,
    /// Seconds since the Unix epoch: the instant every freshness check was
    /// evaluated at — certificate validity windows, both CRLs, and the
    /// `nextUpdate` of the TCB Info and QE Identity.
    pub verified_at: u64,
    /// The DCAP collateral bundle the verification fetched and consumed —
    /// not a second copy, which a cache refresh could make a different one.
    pub dcap_collateral: QuoteCollateralV3,
    /// Digests of the trust anchors compiled into the verifying build.
    pub trust_anchors: TrustAnchors,
}

/// The trust anchors compiled into a verifying build, as digests.
///
/// The one verification input that rides in neither the evidence nor the
/// fetched collateral: Intel's SGX Root CA inside `dcap-qvl`, and the two
/// Azure vTPM root CAs inside the attestation backend. Archiving their bytes
/// would freeze a founding to those exact roots and rule out a rotation that
/// might otherwise repair an old archive; recording digests instead lets a
/// replay notice it runs under different anchors ([`Self::drift_from`])
/// without pinning it to the old ones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustAnchors {
    /// The Azure vTPM root CAs an AK certificate chain is verified against:
    /// SHA-256 of each PEM as compiled into the backend, named by the
    /// backend's asset, in anchor order.
    pub azure_vtpm_roots: Vec<AnchorDigest>,
    /// The `dcap-qvl` version linked. Its Intel SGX Root CA is not reachable
    /// from outside that crate, so the version stands in for the anchor: the
    /// root is pinned by the crate, and the crate by its version.
    ///
    /// TODO(upstream): `dcap-qvl` has `pub static TRUSTED_ROOT_CA_DER` in a
    /// private `constants` module; a one-line `pub use` of it upstream, then
    /// a re-export from the attested-tls fork, would let this field become a
    /// digest like [`Self::azure_vtpm_roots`] and retire the version
    /// stand-in along with `build.rs`.
    pub dcap_qvl_version: String,
}

impl TrustAnchors {
    /// The anchors this build verifies with.
    pub fn compiled_in() -> Self {
        Self {
            azure_vtpm_roots: attestation::azure::AZURE_ROOT_CA_PEMS
                .iter()
                .map(|(name, pem)| AnchorDigest {
                    name: name.to_string(),
                    sha256: Sha256::digest(pem.as_bytes()).into(),
                })
                .collect(),
            // Read from the lockfile by build.rs; see there.
            dcap_qvl_version: env!("SEISMIC_DCAP_QVL_VERSION").to_string(),
        }
    }

    /// How these anchors (an archive's) differ from `current` (a replaying
    /// build's); `None` when they are the same set.
    ///
    /// Drift is information, not a verdict: the replay's cryptographic check
    /// against the current anchors is what decides whether the evidence still
    /// verifies. A caller reports drift so that a verdict reached under other
    /// anchors than the founding's is never mistaken for the founding's own.
    pub fn drift_from(&self, current: &Self) -> Option<AnchorDrift> {
        (self != current).then(|| AnchorDrift {
            archived: self.clone(),
            current: current.clone(),
        })
    }
}

/// One compiled-in trust anchor, by the backend's name for it and the SHA-256
/// of its bytes as compiled in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorDigest {
    pub name: String,
    pub sha256: [u8; 32],
}

/// A replay running under trust anchors other than the ones its verdict was
/// originally reached under. Displays as one line per anchor set that
/// differs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorDrift {
    /// The anchors recorded at verification.
    pub archived: TrustAnchors,
    /// The anchors compiled into the replaying build.
    pub current: TrustAnchors,
}

impl fmt::Display for AnchorDrift {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut lines = Vec::new();
        if self.archived.dcap_qvl_version != self.current.dcap_qvl_version {
            lines.push(format!(
                "dcap-qvl (Intel SGX Root CA) was {} at verification, {} in this build",
                self.archived.dcap_qvl_version, self.current.dcap_qvl_version
            ));
        }
        if self.archived.azure_vtpm_roots != self.current.azure_vtpm_roots {
            let list = |roots: &[AnchorDigest]| {
                roots
                    .iter()
                    .map(|root| format!("{}={}", root.name, hex::encode(root.sha256)))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            lines.push(format!(
                "Azure vTPM roots were [{}] at verification, [{}] in this build",
                list(&self.archived.azure_vtpm_roots),
                list(&self.current.azure_vtpm_roots)
            ));
        }
        f.write_str(&lines.join("; "))
    }
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
    #[error(
        "the verification fetched no DCAP collateral; a Seismic verification requires the fetched \
         collateral, since nothing else lets the verdict be reproduced"
    )]
    NoFetchedDcapCollateral,
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

    /// The anchors a verdict rests on are exactly the two Azure roots the
    /// backend compiles in, digested from the same bytes it verifies with,
    /// plus the version of the crate carrying Intel's root.
    #[test]
    fn compiled_in_anchors_are_the_backends() {
        let anchors = TrustAnchors::compiled_in();

        let names: Vec<&str> = anchors
            .azure_vtpm_roots
            .iter()
            .map(|root| root.name.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "microsoft-rsa-devices-root-ca-2021",
                "azure-virtual-tpm-root-2023"
            ]
        );
        for ((_, pem), root) in attestation::azure::AZURE_ROOT_CA_PEMS
            .iter()
            .zip(&anchors.azure_vtpm_roots)
        {
            assert_eq!(
                root.sha256,
                <[u8; 32]>::from(Sha256::digest(pem.as_bytes()))
            );
        }

        // A crate version, as the lockfile spells it.
        let mut parts = anchors.dcap_qvl_version.split('.');
        for _ in 0..3 {
            parts
                .next()
                .and_then(|part| part.parse::<u32>().ok())
                .unwrap_or_else(|| panic!("not a version: {}", anchors.dcap_qvl_version));
        }
        assert!(parts.next().is_none(), "{}", anchors.dcap_qvl_version);
    }

    /// Drift is detected per anchor set and reported by name, and the same
    /// set reports none.
    #[test]
    fn anchor_drift_is_reported_by_what_changed() {
        let founding = TrustAnchors::compiled_in();
        assert_eq!(founding.drift_from(&TrustAnchors::compiled_in()), None);

        let mut newer_dcap_qvl = founding.clone();
        newer_dcap_qvl.dcap_qvl_version = "9.9.9".to_string();
        let drift = founding.drift_from(&newer_dcap_qvl).unwrap().to_string();
        assert!(drift.contains("dcap-qvl"), "{drift}");
        assert!(drift.contains("9.9.9"), "{drift}");
        assert!(!drift.contains("Azure vTPM roots"), "{drift}");

        let mut rotated_root = founding.clone();
        rotated_root.azure_vtpm_roots.push(AnchorDigest {
            name: "azure-virtual-tpm-root-2031".to_string(),
            sha256: [0x31; 32],
        });
        let drift = founding.drift_from(&rotated_root).unwrap().to_string();
        assert!(drift.contains("Azure vTPM roots"), "{drift}");
        assert!(drift.contains("azure-virtual-tpm-root-2031"), "{drift}");
        assert!(drift.contains(&hex::encode([0x31; 32])), "{drift}");
        assert!(!drift.contains("dcap-qvl"), "{drift}");
    }
}
