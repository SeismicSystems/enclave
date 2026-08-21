//! Wire types, digests, and envelope signing for security-council epoch-key
//! deliveries to the centralized custodian.
//!
//! One envelope carries one 32-byte purpose key for one `(purpose, epoch)`
//! pair, in plaintext, under an Ethereum-wallet signature over the EIP-712
//! typed-data digest of the payload ([`eip712`] — the key appears only as
//! its keccak-256 commitment, so wallets never see it). Confidentiality is
//! the transport's job: the centralized phase runs among known operators
//! who put TLS or a tunnel in front of the council port. Envelopes are
//! self-contained — verification needs only the council address and the
//! network id — so the custodian persists them verbatim (as secrets: they
//! contain the key) and replays verification on every boot.
//!
//! Boundary rule: this crate is a leaf shared between the custodian host and
//! off-node council signer tooling. No custodian, attestation, or async
//! dependencies; epoch sequencing and conflict policy belong to the host.

mod bindings;
mod eip712;
mod envelope;
mod messages;
mod observer;

pub use bindings::network_id_from_chain_id;
pub use eip712::{
    DOMAIN_NAME, DOMAIN_VERSION, address_from_pubkey, key_commitment, payload_digest,
    typed_data_json,
};
pub use envelope::{
    VerifyDeliveryError, canonical_envelope_bytes, envelope_from_bytes, seal_delivery,
    verify_delivery,
};
pub use messages::{
    CouncilRequest, CouncilResponse, CouncilStatus, DeliveryPayload, MAX_ENVELOPES_PER_FETCH,
    ObserverFetchRequest, ObserverQuery, ObserverRejectCode, ObserverRootKey, RejectCode,
    SignedDeliveryEnvelope,
};
pub use observer::{OBSERVER_FETCH_DOMAIN, observer_fetch_signing_payload};
