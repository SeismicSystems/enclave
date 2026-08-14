//! Wire types, digests, and envelope crypto for security-council epoch-key
//! deliveries to the centralized custodian.
//!
//! One envelope carries one 32-byte purpose key for one `(purpose, epoch)`
//! pair: AEAD-encrypted to the custodian's inbox keypair ([`bindings`] holds
//! the AAD) and signed with an ordinary Ethereum wallet over the EIP-712
//! typed-data digest of the complete payload ([`eip712`]). Envelopes are
//! self-contained — verification needs only the council address, the network
//! id, and the inbox key — so the custodian persists them verbatim and
//! replays verification on every boot.
//!
//! Boundary rule: this crate is a leaf shared between the custodian host and
//! off-node council signer tooling. No custodian, attestation, or async
//! dependencies; epoch sequencing and conflict policy belong to the host.

mod bindings;
mod eip712;
mod envelope;
mod messages;

pub use bindings::{delivery_context_binding, network_id_from_chain_id, payload_context_binding};
pub use eip712::{
    DOMAIN_NAME, DOMAIN_VERSION, address_from_pubkey, payload_digest, typed_data_json,
};
pub use envelope::{
    EphemeralKeypair, OpenDeliveryError, canonical_envelope_bytes, envelope_from_bytes,
    open_delivery, seal_delivery,
};
pub use messages::{
    CouncilRequest, CouncilResponse, CouncilStatus, DeliveryPayload, DeliveryPurpose, InboxPk,
    RejectCode, SignedDeliveryEnvelope,
};
