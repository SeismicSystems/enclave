//! Admission of new nodes into the network: an operator boots a fresh box,
//! it asks an existing node for `root_key`, and these predicates are the
//! yes-or-no on letting it in.
//!
//! Holding `root_key` is what makes a machine part of the network's trust
//! domain — every decryption and purpose key derives from it — so the
//! root-key bootstrap handshake, the first mandatory step of any join, is
//! where membership is granted or refused. (Consensus membership — a seat in
//! the validator set — is gated separately.) Cryptographic evidence
//! verification (in `seismic-attestation`) establishes which guest is
//! asking; the predicates here decide whether that guest is allowed:
//!
//! - [`RegistryAdmission`] — the responder's predicate. A requester is
//!   admitted iff its Azure v1 admission ID is currently accepted by the
//!   on-chain `MeasurementRegistry`, asked via `eth_call isAccepted(id)` on
//!   the node's local reth. The chain carries the *live* policy: additions and
//!   deprecations take effect on the next handshake, no node restart needed.
//! - [`DangerouslyAdmitAnyAzureGuest`] — the requester's (joiner's) predicate
//!   for appraising the responder, intentionally permissive; see its docs.
//!
//! The measurements → admission-ID mapping is `seismic-measurement-admission`,
//! the same derivation deploy tooling compiles the registry's genesis storage
//! with — the two halves of the system cannot disagree on what an admission ID
//! means. Every branch fails closed: a non-Azure attestation type, a PCR
//! bank missing a schema register, an unreachable chain, and a false
//! `isAccepted` all deny the handshake.

use alloy::providers::RootProvider;
use alloy_primitives::Address;
use seismic_attestation::{AdmissionPredicate, AttestationType, VerifiedSeismicAttestation};
use seismic_measurement_admission::{AdmissionId, AzureTdxV1Measurements, MissingPcr};
use seismic_measurement_registry_client::MeasurementRegistry::{self, MeasurementRegistryInstance};
use tracing::{info, warn};

/// Why a bootstrap admission predicate denied a verified guest.
#[derive(Debug, thiserror::Error)]
pub enum AdmissionDenial {
    #[error("only Azure TDX guests are admitted to the bootstrap; evidence is {0}")]
    UnsupportedAttestationType(AttestationType),
    #[error(transparent)]
    MissingPcr(#[from] MissingPcr),
    #[error("querying MeasurementRegistry.isAccepted({admission_id}) on local reth: {source}")]
    RegistryQueryFailed {
        admission_id: AdmissionId,
        #[source]
        source: Box<alloy::contract::Error>,
    },
    #[error("admission ID {0} is not accepted by the MeasurementRegistry")]
    NotAccepted(AdmissionId),
}

/// The [`AdmissionId`] of a verified guest, under the Azure v1 schema.
///
/// Fails closed: only Azure TDX attestation has an admission schema, and a
/// verified PCR bank missing any schema register yields an error, never a
/// partial identity.
fn azure_admission_id(
    verified: &VerifiedSeismicAttestation,
) -> Result<AdmissionId, AdmissionDenial> {
    let VerifiedSeismicAttestation::AzureTdx(azure) = verified else {
        return Err(AdmissionDenial::UnsupportedAttestationType(
            verified.attestation_type(),
        ));
    };
    let measurements = AzureTdxV1Measurements::from_pcrs(&azure.guest_measurements.pcrs)?;
    Ok(measurements.admission_id())
}

/// Responder-side admission: registry membership of the requester's
/// admission ID.
#[derive(Clone)]
pub struct RegistryAdmission {
    registry: MeasurementRegistryInstance<RootProvider>,
}

impl RegistryAdmission {
    /// Admission backed by the `MeasurementRegistry` at `registry` (the
    /// manifest's `measurements.contracts.registry`), read over the node's
    /// local reth HTTP endpoint.
    pub fn new(reth_rpc_url: url::Url, registry: Address) -> Self {
        Self::with_provider(RootProvider::new_http(reth_rpc_url), registry)
    }

    fn with_provider(provider: RootProvider, registry: Address) -> Self {
        Self {
            registry: MeasurementRegistry::new(registry, provider),
        }
    }
}

impl AdmissionPredicate for RegistryAdmission {
    async fn admit(
        &self,
        verified: &VerifiedSeismicAttestation,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let admission_id = azure_admission_id(verified)?;
        let accepted = self
            .registry
            .isAccepted(admission_id.into())
            .call()
            .await
            .map_err(|source| AdmissionDenial::RegistryQueryFailed {
                admission_id,
                source: Box::new(source),
            })?;
        if !accepted {
            return Err(AdmissionDenial::NotAccepted(admission_id).into());
        }
        info!("bootstrap: MeasurementRegistry accepted admission ID {admission_id}");
        Ok(())
    }
}

/// Requester-side (joiner) appraisal of the responder: any cryptographically
/// valid Azure TDX guest is admitted, measurements unchecked.
///
/// TODO(bootstrap): intentionally temporary. The joiner cannot hold the live
/// policy — it can't read the chain before it holds `root_key`, and a
/// manifest-pinned allowlist would be frozen at genesis — so its real defense
/// is planned as provenance, not measurement appraisal: verifying the
/// responder against the network's pinned `tx_io_pk` commitment. Until that
/// lands, a joiner talking to an attacker-chosen "responder" enclave gets no
/// measurement guarantee beyond genuine Azure TDX hardware.
pub struct DangerouslyAdmitAnyAzureGuest;

impl AdmissionPredicate for DangerouslyAdmitAnyAzureGuest {
    async fn admit(
        &self,
        verified: &VerifiedSeismicAttestation,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !matches!(verified, VerifiedSeismicAttestation::AzureTdx(_)) {
            return Err(
                AdmissionDenial::UnsupportedAttestationType(verified.attestation_type()).into(),
            );
        }
        warn!(
            "bootstrap: admitting responder on any Azure TDX measurements; \
             its image is NOT being checked against the network policy"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{rpc::client::RpcClient, transports::mock::Asserter};
    use alloy_primitives::{Bytes, b256};
    use seismic_attestation::{AzureGuestMeasurements, VerifiedAzureAttestation};
    use std::collections::HashMap;

    // The golden Azure v1 vector pinned in `seismic-measurement-admission`:
    // this tuple's admission ID must match that crate's derivation exactly.
    const PCR4: [u8; 32] = [0x11; 32];
    const PCR9: [u8; 32] = [0x22; 32];
    const PCR11: [u8; 32] = [0x33; 32];
    const GOLDEN_ADMISSION_ID: alloy_primitives::B256 =
        b256!("0x0e4c78c6346c15ad1fbbcf16dab1ab9e5c820f4daf5b8001c92d1f40f0f16a8e");

    fn verified_azure(pcrs: HashMap<u32, [u8; 32]>) -> VerifiedSeismicAttestation {
        VerifiedSeismicAttestation::AzureTdx(VerifiedAzureAttestation {
            binding: [0u8; 64],
            guest_measurements: AzureGuestMeasurements { pcrs },
        })
    }

    fn golden_pcr_bank() -> HashMap<u32, [u8; 32]> {
        HashMap::from([(4, PCR4), (9, PCR9), (11, PCR11)])
    }

    fn mocked_registry(asserter: &Asserter) -> RegistryAdmission {
        RegistryAdmission::with_provider(
            RootProvider::new(RpcClient::mocked(asserter.clone())),
            Address::ZERO,
        )
    }

    /// ABI-encoded `isAccepted` return value, as the eth_call response body.
    fn abi_bool(value: bool) -> Bytes {
        let mut word = [0u8; 32];
        word[31] = value as u8;
        Bytes::from(word.to_vec())
    }

    #[test]
    fn derives_golden_admission_id_from_verified_measurements() {
        // Extra registers in the verified bank don't perturb identity.
        let mut pcrs = golden_pcr_bank();
        pcrs.insert(0, [0xaa; 32]);
        assert_eq!(
            azure_admission_id(&verified_azure(pcrs)).unwrap(),
            AdmissionId::from(GOLDEN_ADMISSION_ID)
        );
    }

    #[test]
    fn missing_schema_pcr_fails_closed() {
        let mut pcrs = golden_pcr_bank();
        pcrs.remove(&9);
        assert!(matches!(
            azure_admission_id(&verified_azure(pcrs)),
            Err(AdmissionDenial::MissingPcr(MissingPcr(9)))
        ));
    }

    #[test]
    fn non_azure_attestation_fails_closed() {
        let verified = VerifiedSeismicAttestation::NoAttestation { binding: [0u8; 64] };
        assert!(matches!(
            azure_admission_id(&verified),
            Err(AdmissionDenial::UnsupportedAttestationType(
                AttestationType::None
            ))
        ));
    }

    #[tokio::test]
    async fn accepted_tuple_is_admitted() {
        let asserter = Asserter::new();
        asserter.push_success(&abi_bool(true));
        let admission = mocked_registry(&asserter);

        admission
            .admit(&verified_azure(golden_pcr_bank()))
            .await
            .expect("registry-accepted tuple must be admitted");
    }

    #[tokio::test]
    async fn unknown_tuple_is_denied() {
        let asserter = Asserter::new();
        asserter.push_success(&abi_bool(false));
        let admission = mocked_registry(&asserter);

        let error = admission
            .admit(&verified_azure(golden_pcr_bank()))
            .await
            .expect_err("tuple the registry rejects must be denied");
        assert!(error.to_string().contains("not accepted"), "{error}");
    }

    #[tokio::test]
    async fn unreachable_registry_fails_closed() {
        let asserter = Asserter::new();
        asserter.push_failure_msg("connection refused");
        let admission = mocked_registry(&asserter);

        let error = admission
            .admit(&verified_azure(golden_pcr_bank()))
            .await
            .expect_err("an unreachable registry must deny, not admit");
        assert!(error.to_string().contains("isAccepted"), "{error}");
    }

    #[tokio::test]
    async fn missing_pcr_denies_without_asking_the_registry() {
        // No queued response: reaching the registry would error differently,
        // so a MissingPcr denial proves the RPC was never attempted.
        let admission = mocked_registry(&Asserter::new());
        let mut pcrs = golden_pcr_bank();
        pcrs.remove(&11);

        let error = admission
            .admit(&verified_azure(pcrs))
            .await
            .expect_err("missing schema register must fail closed");
        assert!(error.to_string().contains("pcr11"), "{error}");
    }

    #[tokio::test]
    async fn joiner_predicate_admits_azure_and_denies_other_types() {
        DangerouslyAdmitAnyAzureGuest
            .admit(&verified_azure(HashMap::new()))
            .await
            .expect("any Azure guest is admitted by the temporary predicate");

        DangerouslyAdmitAnyAzureGuest
            .admit(&VerifiedSeismicAttestation::NoAttestation { binding: [0u8; 64] })
            .await
            .expect_err("non-Azure attestation types are denied even by the temporary predicate");
    }
}
