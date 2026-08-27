//! The canonical rendering of a [`NetworkManifestV1`] — the bytes whose
//! SHA-256 is the network's identity.
//!
//! This crate is the manifest's only emitter, and it lives apart from the
//! schema crate on purpose: `seismic-network-manifest` is parse-only, so a
//! node build (tdx-init, the attestation service) has no code path that
//! re-serializes the file — any re-rendering would risk changing the bytes
//! and therefore the `network_id`. Deploy tooling links this crate (or runs
//! the `seismic-manifest` binary) to render; nodes only ever parse.
//!
//! Rendering is deterministic so the same values always name the same
//! network: 2-space indent, keys in sorted order at every level, `": "` after
//! each key, integers unquoted, hex lowercase and `0x`-prefixed, raw UTF-8,
//! one trailing newline. The schema crate's `fixtures/network-manifest-v1.json`
//! pins the exact bytes; the round-trip test below holds `parse → render` to
//! them.

pub use seismic_network_manifest::{
    ContractsManifest, EthManifest, ManifestError, MeasurementsManifest, NetworkId,
    NetworkManifestV1, SummitManifest,
};
use serde_json::json;

/// Render the canonical `network-manifest.json` bytes for these values.
///
/// Render once, then let the bytes travel verbatim: `network_id` is a hash of
/// the file, so any re-rendering downstream would risk naming a different
/// network.
pub fn render(manifest: &NetworkManifestV1) -> Vec<u8> {
    // Destructured field by field: any future addition or change to
    // NetworkManifestV1 fails to compile here, so whoever makes it updates
    // the rendering below.
    let NetworkManifestV1 {
        manifest_version,
        name,
        eth,
        summit,
        measurements,
    } = manifest;
    let EthManifest {
        chain_id,
        genesis_hash,
    } = eth;
    let SummitManifest {
        genesis_config_digest,
        namespace,
    } = summit;
    let MeasurementsManifest {
        bootstrap_policy_hash,
        contracts,
    } = measurements;
    let ContractsManifest {
        registry,
        authority,
    } = contracts;

    // Sorted keys are the canonical form: the one a holder of the file can
    // reproduce with no schema in hand, since `jq -S .` over these bytes
    // returns them unchanged. The literal below is kept sorted to read the
    // way the artifact does, but `sort_keys` is what guarantees it.
    let mut value = json!({
        "eth": {
            "chain_id": chain_id,
            "genesis_hash": hex_0x(genesis_hash),
        },
        "manifest_version": manifest_version,
        "measurements": {
            "bootstrap_policy_hash": hex_0x(bootstrap_policy_hash),
            "contracts": {
                "authority": hex_0x(authority),
                "registry": hex_0x(registry),
            },
        },
        "name": name,
        "summit": {
            "genesis_config_digest": hex_0x(genesis_config_digest),
            "namespace": namespace,
        },
    });
    sort_keys(&mut value);
    let mut bytes = serde_json::to_vec_pretty(&value)
        .expect("a manifest built from parsed values always serializes");
    bytes.push(b'\n');
    bytes
}

/// Put every object's keys in sorted order.
///
/// Which order `serde_json` would otherwise emit depends on a feature no
/// single crate controls: `preserve_order` swaps `Map` from a `BTreeMap` to an
/// `IndexMap`, and cargo unifies it across whatever is being built — on for a
/// `--workspace` build here (dcap-qvl pulls it in), off for a standalone
/// `cargo install` of this crate. Sorting explicitly makes the two builds emit
/// the same bytes, so the network_id never depends on how the tool was built.
fn sort_keys(value: &mut serde_json::Value) {
    if let serde_json::Value::Object(map) = value {
        let mut entries: Vec<_> = std::mem::take(map).into_iter().collect();
        entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (_, nested) in entries.iter_mut() {
            sort_keys(nested);
        }
        *map = entries.into_iter().collect();
    }
}

fn hex_0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] =
        include_bytes!("../../../crates/network-manifest/fixtures/network-manifest-v1.json");
    const FIXTURE_NETWORK_ID: &str =
        "0x8ef142e3f2bf15f8b201c4d8cda7848a9e846222c62b5615d4d36c7fccd98a24";

    #[test]
    fn render_reproduces_fixture_bytes() {
        let manifest = NetworkManifestV1::from_json_bytes(FIXTURE).unwrap();
        let rendered = render(&manifest);
        assert_eq!(std::str::from_utf8(&rendered), std::str::from_utf8(FIXTURE));
        assert_eq!(
            NetworkId::from_manifest_bytes(&rendered).to_string(),
            FIXTURE_NETWORK_ID
        );
    }

    #[test]
    fn render_is_canonical_regardless_of_input_formatting() {
        // Same values, hostile formatting: reversed key order, no whitespace,
        // uppercase hex. The renderer owns the bytes, not the input.
        let value: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
        let compact = serde_json::to_string(&value)
            .unwrap()
            .replace("0xbbbb", "0xBBBB");
        let reversed = {
            let obj = value.as_object().unwrap();
            let mut keys: Vec<_> = obj.keys().collect();
            keys.reverse();
            let mut s = String::from("{");
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push_str(&format!(
                    "{}:{}",
                    serde_json::to_string(k).unwrap(),
                    obj[*k]
                ));
            }
            s.push('}');
            s
        };
        for input in [compact, reversed] {
            let manifest = NetworkManifestV1::from_json_bytes(input.as_bytes()).unwrap();
            assert_eq!(render(&manifest), FIXTURE);
        }
    }

    #[test]
    fn sort_keys_orders_every_level() {
        let mut value = json!({"b": 1, "a": {"d": 2, "c": {"f": 4, "e": 5}}});
        sort_keys(&mut value);
        assert_eq!(
            serde_json::to_string(&value).unwrap(),
            r#"{"a":{"c":{"e":5,"f":4},"d":2},"b":1}"#
        );
    }

    #[test]
    fn render_escapes_strings_as_json_requires() {
        // Non-ASCII passes through as UTF-8 (never \u-escaped); quotes and
        // control characters are escaped. The rendered bytes must still parse
        // back to the same values.
        let mut manifest = NetworkManifestV1::from_json_bytes(FIXTURE).unwrap();
        manifest.name = "réseau \"un\"\ttab".to_string();
        let rendered = render(&manifest);
        assert!(
            std::str::from_utf8(&rendered)
                .unwrap()
                .contains(r#""name": "réseau \"un\"\ttab""#)
        );
        assert_eq!(
            NetworkManifestV1::from_json_bytes(&rendered).unwrap(),
            manifest
        );
    }
}
