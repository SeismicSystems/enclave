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
//!   on-chain `MeasurementRegistry`, asked via `eth_call isAccepted(id)`
//!   pinned to a provably fresh finalized block of the node's local reth
//!   (see `fresh_policy_block`). The chain carries the *live* policy:
//!   additions and deprecations take effect on the next handshake, no node
//!   restart needed.
//! - [`DangerouslyAdmitAnyAzureGuest`] — the requester's (joiner's) predicate
//!   for appraising the responder, intentionally permissive; see its docs.
//!
//! The measurements → admission-ID mapping is `seismic-measurement-admission`,
//! the same derivation deploy tooling compiles the registry's genesis storage
//! with — the two halves of the system cannot disagree on what an admission ID
//! means. Every branch fails closed: a non-Azure attestation type, a PCR
//! bank missing a schema register, an unreachable or stale chain, and a false
//! `isAccepted` all deny the handshake.
//!
//! The freshness gate measures staleness against the guest's wall clock, so
//! it defends against a lagging, partitioned, or network-eclipsed node — not
//! against a malicious host that both eclipses the node and controls the
//! guest's clock. That residual risk is accepted host influence under the
//! TEE threat model.

use alloy::{
    eips::{BlockId, BlockNumberOrTag},
    providers::{Provider, RootProvider},
    rpc::types::Block,
    transports::TransportError,
};
use alloy_primitives::{Address, B256};
use seismic_attestation::{AdmissionPredicate, AttestationType, VerifiedSeismicAttestation};
use seismic_measurement_admission::{AdmissionId, AzureTdxV1Measurements, MissingPcr};
use seismic_measurement_registry_client::MeasurementRegistry::{self, MeasurementRegistryInstance};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{info, warn};

/// Why a bootstrap admission predicate denied a verified guest.
#[derive(Debug, thiserror::Error)]
pub enum AdmissionDenial {
    #[error("only Azure TDX guests are admitted to the bootstrap; evidence is {0}")]
    UnsupportedAttestationType(AttestationType),
    #[error(transparent)]
    MissingPcr(#[from] MissingPcr),
    #[error("admission ID {0} is not accepted by the MeasurementRegistry")]
    RegistryNotAccepted(AdmissionId),
    #[error("querying MeasurementRegistry.isAccepted({admission_id}) on local reth: {source}")]
    RegistryQueryFailed {
        admission_id: AdmissionId,
        #[source]
        source: Box<alloy::contract::Error>,
    },
    #[error("querying local reth for the {tag} block: {source}")]
    ChainQueryFailed {
        tag: BlockNumberOrTag,
        #[source]
        source: Box<TransportError>,
    },
    #[error("local reth has no {tag} block")]
    ChainBlockMissing { tag: BlockNumberOrTag },
    #[error(
        "finalized block {number} is {age_secs}s old (bound: {max_age_secs}s); \
         refusing to admit on a possibly stale policy view"
    )]
    ChainStale {
        number: u64,
        age_secs: u64,
        max_age_secs: u64,
    },
    #[error("local reth is at genesis after chain progress was observed")]
    ChainRegressedToGenesis,
}

impl AdmissionDenial {
    /// Whether this denial is the responder failing to *decide* — the local
    /// chain or registry read did not produce a usable answer — as opposed to
    /// a verdict on the requester (whose evidence will keep failing the same
    /// way). Transient denials are worth retrying: against the same responder
    /// moments later, or against another responder entirely.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::RegistryQueryFailed { .. }
            | Self::ChainQueryFailed { .. }
            | Self::ChainBlockMissing { .. }
            | Self::ChainStale { .. }
            | Self::ChainRegressedToGenesis => true,
            Self::UnsupportedAttestationType(_)
            | Self::MissingPcr(_)
            | Self::RegistryNotAccepted(_) => false,
        }
    }
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

/// Upper bound on the age of the finalized block an admission decision is
/// allowed to read the policy at. This is the longest an eclipsed or lagging
/// responder can keep admitting on an allowlist the network has since
/// deprecated, so smaller is stricter; summit finalizes within seconds, so
/// a minute of slack denies nothing in healthy operation, and a joiner
/// refused during a brief stall simply retries.
const MAX_POLICY_AGE: Duration = Duration::from_secs(60);

/// Responder-side admission: registry membership of the requester's
/// admission ID, decided at fresh local chain state.
#[derive(Clone)]
pub struct RegistryAdmission {
    registry: MeasurementRegistryInstance<RootProvider>,
    /// Latched once any admission observes the chain past genesis. The
    /// genesis admission window (see `fresh_policy_block`) never reopens
    /// within this process: a reth back at block 0 after progress was
    /// observed has been wiped or replaced, and must not admit on its say-so.
    chain_has_advanced: Arc<AtomicBool>,
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
            chain_has_advanced: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The block to answer `isAccepted` at: local reth's finalized block,
    /// proven fresh. Pinning the query to this exact hash means the policy
    /// answer comes from the state that passed the freshness check, not from
    /// whatever "latest" happens to be a moment later.
    ///
    /// Freshness is the finalized block's timestamp against the guest's wall
    /// clock. A lagging or eclipsed node cannot see the true chain head, so
    /// no local comparison of heights can detect staleness — a recent
    /// timestamp is the one locally checkable witness that this view of the
    /// allowlist is current. The finalized tag (summit publishes it
    /// every forkchoice update, trailing head by at most a block or two)
    /// additionally guarantees the decision can never sit on a block that
    /// reorgs away.
    ///
    /// The one exception is a chain still at genesis, where finality is not
    /// yet being published and the genesis timestamp is arbitrarily old.
    /// Admitting there is sound by construction — block-0 state *is* the
    /// genesis-pinned policy, and no deprecation can predate the chain — and
    /// it is what lets the founding cohort join before consensus starts.
    async fn fresh_policy_block(&self) -> Result<B256, AdmissionDenial> {
        let latest = self.block_by_tag(BlockNumberOrTag::Latest).await?;
        if latest.header.inner.number == 0 {
            if self.chain_has_advanced.load(Ordering::Relaxed) {
                return Err(AdmissionDenial::ChainRegressedToGenesis);
            }
            return Ok(latest.header.hash);
        }
        self.chain_has_advanced.store(true, Ordering::Relaxed);

        let finalized = self.block_by_tag(BlockNumberOrTag::Finalized).await?;
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let age_secs = now_secs.saturating_sub(finalized.header.inner.timestamp);
        if age_secs > MAX_POLICY_AGE.as_secs() {
            return Err(AdmissionDenial::ChainStale {
                number: finalized.header.inner.number,
                age_secs,
                max_age_secs: MAX_POLICY_AGE.as_secs(),
            });
        }
        Ok(finalized.header.hash)
    }

    async fn block_by_tag(&self, tag: BlockNumberOrTag) -> Result<Block, AdmissionDenial> {
        self.registry
            .provider()
            .get_block_by_number(tag)
            .await
            .map_err(|source| AdmissionDenial::ChainQueryFailed {
                tag,
                source: Box::new(source),
            })?
            .ok_or(AdmissionDenial::ChainBlockMissing { tag })
    }

    /// One attempt at the chain-backed decision: fresh policy block, then the
    /// registry's verdict for `admission_id` at exactly that block.
    async fn decide(&self, admission_id: AdmissionId) -> Result<(), AdmissionDenial> {
        let policy_block = self.fresh_policy_block().await?;
        let accepted = self
            .registry
            .isAccepted(admission_id.into())
            .block(BlockId::hash(policy_block))
            .call()
            .await
            .map_err(|source| AdmissionDenial::RegistryQueryFailed {
                admission_id,
                source: Box::new(source),
            })?;
        if !accepted {
            return Err(AdmissionDenial::RegistryNotAccepted(admission_id));
        }
        info!(
            "bootstrap: MeasurementRegistry accepted admission ID {admission_id} \
             at block {policy_block}"
        );
        Ok(())
    }
}

/// How many times `admit` attempts the chain-backed decision, and the pause
/// between attempts. By this point the requester's evidence has already
/// verified — the expensive half of the handshake, a fresh quote per try on
/// the joiner — so a local reth that is restarting, or just catching back
/// under the freshness bound, deserves a few seconds' grace before the
/// handshake is failed and the joiner has to start over. Bounded small so a
/// genuinely stale responder still answers well within the joiner's request
/// timeout.
const DECIDE_ATTEMPTS: u32 = 3;
const DECIDE_RETRY_DELAY: Duration = Duration::from_secs(2);

impl AdmissionPredicate for RegistryAdmission {
    async fn admit(
        &self,
        verified: &VerifiedSeismicAttestation,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let admission_id = azure_admission_id(verified)?;
        let mut attempt = 1;
        loop {
            match self.decide(admission_id).await {
                Err(denial) if denial.is_transient() && attempt < DECIDE_ATTEMPTS => {
                    warn!(
                        "bootstrap: admission attempt {attempt}/{DECIDE_ATTEMPTS} \
                         hit a transient failure, retrying: {denial}"
                    );
                    attempt += 1;
                    tokio::time::sleep(DECIDE_RETRY_DELAY).await;
                }
                decision => return decision.map_err(Into::into),
            }
        }
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

    /// An `eth_getBlockByNumber` response body, with a hash derived from the
    /// block number so distinct blocks are tellable apart.
    fn rpc_block(number: u64, timestamp: u64) -> Block {
        let mut block: Block = Block::default();
        block.header.hash = alloy_primitives::B256::with_last_byte(number as u8);
        block.header.inner.number = number;
        block.header.inner.timestamp = timestamp;
        block
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_secs()
    }

    /// Queue responses for the two chain reads `admit` issues before the
    /// registry call. The [`Asserter`] is parameter-blind and serves queued
    /// responses in request order, so these stand in for the `latest`-tag and
    /// `finalized`-tag queries respectively; that the code really asks with
    /// those tags (and pins the registry call to the finalized hash) is
    /// proven by `policy_read_is_pinned_to_the_fresh_finalized_block`.
    fn push_fresh_chain(asserter: &Asserter) {
        asserter.push_success(&rpc_block(7, now_secs()));
        asserter.push_success(&rpc_block(6, now_secs()));
    }

    /// A parameter-checking reth stand-in: serves `latest` and `finalized`
    /// blocks by tag, errors on any other `eth_getBlockByNumber` query, and
    /// answers `isAccepted` with `true` only when the `eth_call` is pinned
    /// to the finalized block's hash. Any admission that queries the wrong
    /// tag or reads the policy at any other block therefore fails.
    async fn spawn_tag_checking_reth(latest: Block, finalized: Block) -> String {
        use jsonrpsee::{server::ServerBuilder, types::ErrorObjectOwned};

        fn unexpected(message: String) -> ErrorObjectOwned {
            ErrorObjectOwned::owned(-32000, message, None::<()>)
        }

        let server = ServerBuilder::default()
            .build("127.0.0.1:0")
            .await
            .expect("bind mock reth endpoint");
        let addr = server.local_addr().expect("mock reth local addr");
        let finalized_hash = finalized.header.hash;
        let mut module = jsonrpsee::RpcModule::new(());
        module
            .register_method("eth_getBlockByNumber", move |params, _, _| {
                let (tag, _full_transactions): (String, bool) = params.parse()?;
                let block = match tag.as_str() {
                    "latest" => &latest,
                    "finalized" => &finalized,
                    other => return Err(unexpected(format!("unexpected block tag {other}"))),
                };
                Ok(serde_json::to_value(block).expect("serialize mock block"))
            })
            .expect("register eth_getBlockByNumber");
        module
            .register_method("eth_call", move |params, _, _| {
                let (_call, block_id): (serde_json::Value, serde_json::Value) = params.parse()?;
                let pinned = block_id
                    .get("blockHash")
                    .cloned()
                    .and_then(|hash| serde_json::from_value::<alloy_primitives::B256>(hash).ok())
                    .ok_or_else(|| {
                        unexpected(format!("eth_call not pinned to a block hash: {block_id}"))
                    })?;
                if pinned != finalized_hash {
                    return Err(unexpected(format!(
                        "eth_call pinned to {pinned}, not the finalized block {finalized_hash}"
                    )));
                }
                const ABI_ENCODED_TRUE: &str =
                    "0x0000000000000000000000000000000000000000000000000000000000000001";
                Ok(serde_json::Value::String(ABI_ENCODED_TRUE.to_string()))
            })
            .expect("register eth_call");
        let handle = server.start(module);
        // The server stops when its handle drops; park the handle in a task
        // that outlives the test body.
        tokio::spawn(handle.stopped());
        format!("http://{addr}")
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
    async fn policy_read_is_pinned_to_the_fresh_finalized_block() {
        // The mock denies every request except the two tag queries and an
        // eth_call at exactly the finalized hash, so this admission succeeding
        // proves the gate reads the finalized tag and pins the registry query
        // to the block it freshness-checked.
        let url = spawn_tag_checking_reth(rpc_block(7, now_secs()), rpc_block(6, now_secs())).await;
        let admission = RegistryAdmission::new(url.parse().expect("mock reth URL"), Address::ZERO);

        admission
            .admit(&verified_azure(golden_pcr_bank()))
            .await
            .expect("admission at the pinned fresh finalized block must succeed");
    }

    #[tokio::test]
    async fn accepted_tuple_is_admitted() {
        let asserter = Asserter::new();
        push_fresh_chain(&asserter);
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
        push_fresh_chain(&asserter);
        asserter.push_success(&abi_bool(false));
        let admission = mocked_registry(&asserter);

        let error = admission
            .admit(&verified_azure(golden_pcr_bank()))
            .await
            .expect_err("tuple the registry rejects must be denied");
        // A registry verdict is final, not transient: no responses are queued
        // for a second attempt, so a retry would surface a chain error here
        // instead of the verdict.
        assert!(error.to_string().contains("not accepted"), "{error}");
    }

    // Transient denials are retried DECIDE_ATTEMPTS times within one
    // handshake, so the denial tests below queue one round of responses per
    // attempt, and pause tokio's clock so the between-attempt sleeps cost the
    // suite nothing.

    #[tokio::test(start_paused = true)]
    async fn unreachable_chain_fails_closed() {
        let asserter = Asserter::new();
        for _ in 0..DECIDE_ATTEMPTS {
            asserter.push_failure_msg("connection refused");
        }
        let admission = mocked_registry(&asserter);

        let error = admission
            .admit(&verified_azure(golden_pcr_bank()))
            .await
            .expect_err("an unreachable chain must deny, not admit");
        assert!(error.to_string().contains("latest block"), "{error}");
    }

    #[tokio::test(start_paused = true)]
    async fn unreachable_registry_fails_closed() {
        let asserter = Asserter::new();
        for _ in 0..DECIDE_ATTEMPTS {
            push_fresh_chain(&asserter);
            asserter.push_failure_msg("connection refused");
        }
        let admission = mocked_registry(&asserter);

        let error = admission
            .admit(&verified_azure(golden_pcr_bank()))
            .await
            .expect_err("an unreachable registry must deny, not admit");
        assert!(error.to_string().contains("isAccepted"), "{error}");
    }

    #[tokio::test(start_paused = true)]
    async fn stale_finalized_view_is_denied() {
        let asserter = Asserter::new();
        for _ in 0..DECIDE_ATTEMPTS {
            asserter.push_success(&rpc_block(7, now_secs()));
            asserter.push_success(&rpc_block(6, now_secs() - 3600));
        }
        let admission = mocked_registry(&asserter);

        let error = admission
            .admit(&verified_azure(golden_pcr_bank()))
            .await
            .expect_err("a stale finalized view must deny, not admit");
        assert!(error.to_string().contains("stale"), "{error}");
    }

    #[tokio::test(start_paused = true)]
    async fn missing_finalized_block_is_denied() {
        // Reth answers `finalized` with an error until consensus publishes a
        // forkchoice update; the mock's null response covers the same branch.
        let asserter = Asserter::new();
        for _ in 0..DECIDE_ATTEMPTS {
            asserter.push_success(&rpc_block(7, now_secs()));
            asserter.push_success(&serde_json::Value::Null);
        }
        let admission = mocked_registry(&asserter);

        let error = admission
            .admit(&verified_azure(golden_pcr_bank()))
            .await
            .expect_err("chain progress without a finalized block must deny");
        assert!(error.to_string().contains("no finalized block"), "{error}");
    }

    #[tokio::test(start_paused = true)]
    async fn transient_chain_failure_is_retried_within_the_handshake() {
        // First attempt fails at the chain read; the retry finds a fresh
        // chain and an accepting registry. The handshake must succeed without
        // the joiner having to start over.
        let asserter = Asserter::new();
        asserter.push_failure_msg("connection refused");
        push_fresh_chain(&asserter);
        asserter.push_success(&abi_bool(true));
        let admission = mocked_registry(&asserter);

        admission
            .admit(&verified_azure(golden_pcr_bank()))
            .await
            .expect("a transient chain failure must be retried, not surfaced");
    }

    #[tokio::test]
    async fn genesis_window_admits_at_block_zero() {
        // The genesis timestamp is far in the past; the window ignores it.
        let asserter = Asserter::new();
        asserter.push_success(&rpc_block(0, 1_000));
        asserter.push_success(&abi_bool(true));
        let admission = mocked_registry(&asserter);

        admission
            .admit(&verified_azure(golden_pcr_bank()))
            .await
            .expect("an accepted tuple must be admitted while the chain is at genesis");
    }

    #[tokio::test(start_paused = true)]
    async fn genesis_window_never_reopens_after_progress() {
        let asserter = Asserter::new();
        push_fresh_chain(&asserter);
        asserter.push_success(&abi_bool(true));
        let admission = mocked_registry(&asserter);
        admission
            .admit(&verified_azure(golden_pcr_bank()))
            .await
            .expect("fresh chain past genesis must admit");

        for _ in 0..DECIDE_ATTEMPTS {
            asserter.push_success(&rpc_block(0, now_secs()));
        }
        let error = admission
            .admit(&verified_azure(golden_pcr_bank()))
            .await
            .expect_err("a chain back at genesis after progress must deny");
        assert!(error.to_string().contains("genesis"), "{error}");
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
