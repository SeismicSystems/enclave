//! The derivation namespace for custodian observer keys.
//!
//! Summit's P2P observer identities mix in `chain_domain(genesis digest)`, a
//! value a custodian cannot compute (it has no genesis file). The custodian
//! protocol instead derives its namespace from the EVM chain id both sides
//! already require — the same convention as council-delivery's
//! `network_id_from_chain_id`, under its own domain tag. Same master key and
//! index therefore yield *different* identities for custodian auth and for
//! P2P — deliberate key-separation between the protocols.

use sha2::{Digest as _, Sha256};

/// Domain for [`observer_namespace_from_chain_id`]. Distinct from
/// council-delivery's `seismic-council-chain-id-v1:` and summit's
/// `summit-chain-v1`.
const OBSERVER_NAMESPACE_DOMAIN: &[u8] = b"seismic-observer-namespace-v1:";

/// The 32-byte derivation namespace for a deployment, from its chain id.
/// Scopes observer child keys to one chain: a signer derived for one
/// deployment can never authenticate on another.
pub fn observer_namespace_from_chain_id(chain_id: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(OBSERVER_NAMESPACE_DOMAIN);
    hasher.update(chain_id.to_be_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vector: the namespace scopes every derived observer identity;
    /// it must never change.
    #[test]
    fn namespace_matches_golden_vector() {
        assert_eq!(
            hex::encode(observer_namespace_from_chain_id(5124)),
            "004e876ed466c4a59fa187e22e9e2da481cfb15d6f14e6f252a8cb1c5c90ed90",
        );
        assert_ne!(
            observer_namespace_from_chain_id(1),
            observer_namespace_from_chain_id(2),
            "distinct chains must scope independently"
        );
    }

    /// The namespace and the council network id share a chain id but must
    /// live in separate domains.
    #[test]
    fn distinct_from_council_network_id() {
        // network_id_from_chain_id(5124), pinned in council-delivery.
        let council = "cae8a2afaa2c48c2d13164b87f8b3ca8056902bad2cd32a8d457e385b50771a6";
        assert_ne!(hex::encode(observer_namespace_from_chain_id(5124)), council);
    }
}
