//! Startup load of the network manifest: this node's [`NetworkId`] plus the
//! parsed manifest fields the service consumes (the registry address).
//!
//! tdx-init writes the network's `network-manifest.json` verbatim into its
//! conf dir (tmpfs, re-supplied every boot by deploy tooling; see
//! [`crate::conf`]).
//! The enclave hashes *those exact bytes* — `network_id = SHA-256(file bytes)`
//! — and threads the result through every attestation binding, so a quote
//! minted on one network can never satisfy a handshake on a clone.
//!
//! We hash the raw bytes we read rather than trusting any precomputed id, and
//! deliberately never parse-and-re-serialize: re-rendering could change the
//! bytes and therefore the id. The strict v1 parse also fails fast with an
//! actionable error on a malformed or wrong-version manifest, but the id
//! always comes from [`NetworkId::from_manifest_bytes`] over the file bytes.

use std::path::Path;

use anyhow::{Context, Result};
use seismic_attestation::{NetworkId, NetworkManifestV1};

/// Read the manifest from `path`, strictly parse it as v1, and derive the
/// [`NetworkId`] from the exact file bytes.
pub fn load_manifest(path: &Path) -> Result<(NetworkManifestV1, NetworkId)> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading network manifest from {}", path.display()))?;

    let manifest = NetworkManifestV1::from_json_bytes(&bytes)
        .with_context(|| format!("parsing network manifest at {}", path.display()))?;

    Ok((manifest, NetworkId::from_manifest_bytes(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const FIXTURE: &[u8] =
        include_bytes!("../../../crates/network-manifest/fixtures/network-manifest-v1.json");

    #[test]
    fn derives_network_id_and_manifest_from_file() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(FIXTURE).unwrap();
        let (manifest, network_id) = load_manifest(tmp.path()).unwrap();
        // Same vector as seismic-attestation's manifest test over the fixture.
        assert_eq!(network_id, NetworkId::from_manifest_bytes(FIXTURE));
        assert_eq!(
            hex::encode(manifest.measurements.contracts.registry),
            "1000000000000000000000000000000000000001"
        );
    }

    #[test]
    fn rejects_malformed_manifest() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"{ not valid json").unwrap();
        assert!(load_manifest(tmp.path()).is_err());
    }

    #[test]
    fn errors_when_manifest_missing() {
        assert!(load_manifest(Path::new("/nonexistent/network-manifest.json")).is_err());
    }
}
