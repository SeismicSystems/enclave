//! The network identifier for council deliveries.
//!
//! The centralized phase has no network-manifest artifact, so the 32-byte
//! network id derives from the EVM chain id via a domain-separated SHA-256
//! (the repo's binding convention). It scopes every delivery signature to
//! one chain — the EIP-712 domain salt — so a council envelope for one
//! network can never replay onto another.

use seismic_network_manifest::NetworkId;
use sha2::{Digest as _, Sha256};

/// Domain for [`network_id_from_chain_id`].
const CHAIN_ID_DOMAIN: &[u8] = b"seismic-council-chain-id-v1:";

/// The centralized deployment's network identifier, derived from the EVM
/// chain id instead of a network-manifest hash. Domain-separated so it can
/// never collide with a manifest-derived id, and reproducible by council
/// tooling from the chain id alone.
pub fn network_id_from_chain_id(chain_id: u64) -> NetworkId {
    let mut hasher = Sha256::new();
    hasher.update(CHAIN_ID_DOMAIN);
    hasher.update(chain_id.to_be_bytes());
    NetworkId::from_bytes(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vector: the chain-id-derived network id scopes every
    /// signature; it must never change, and council tooling must derive the
    /// identical value.
    #[test]
    fn chain_id_network_id_matches_golden_vector() {
        assert_eq!(
            hex::encode(network_id_from_chain_id(5124).as_bytes()),
            "cae8a2afaa2c48c2d13164b87f8b3ca8056902bad2cd32a8d457e385b50771a6",
        );
        assert_ne!(
            network_id_from_chain_id(1),
            network_id_from_chain_id(2),
            "distinct chains must scope independently"
        );
    }
}
