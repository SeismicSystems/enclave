//! The checks across `[network]`'s three artifacts: the manifest and the two
//! genesis files it pins.
//!
//! They live here, beside the schema, so `tdx-init` and deploy tooling run the
//! same code: `tdx-init` on every POST (`:8080` is unauthenticated and the
//! operator untrusted, so the node never relies on the sender having checked),
//! deploy tooling before it POSTs, so a bad input fails while the fix still
//! costs nothing.
//!
//! The manifest is the network's identity: `network_id = SHA-256(exact file
//! bytes)`. Its `eth.genesis_hash` commits to the reth genesis and its
//! `summit.genesis_config_digest` to the summit genesis, so the three are one
//! assembled set. These checks don't recompute either commitment: that would
//! need reth's chain-spec parse path (`keccak(rlp(header))`) and summit's SSZ
//! layout, and a second implementation that diverges rejects valid networks.
//! They check instead the fields the manifest duplicates for exactly this
//! purpose (`eth.chain_id`, `summit.namespace`). The hashes are deploy
//! tooling's to recompute with reth's and summit's own code; on a node, a
//! divergent reth genesis produces a block 0 its peers reject, and a divergent
//! summit genesis a `chain_domain(config_digest)` no handshake matches.
//!
//! Each artifact travels base64-encoded and is decoded to the exact bytes to
//! write: reth, summit and every `network_id` derivation read the file
//! themselves, so nothing here re-renders it.

use crate::InitConfig;
use base64::Engine;
use seismic_network_manifest::{ManifestError, NetworkId, NetworkManifestV1};
use serde::Deserialize;

/// `[network]` after [`InitConfig::validate`]: the decoded bytes of each
/// artifact, exactly as they are to be written, and the parsed manifest.
///
/// Only [`InitConfig::validate`] builds one, so holding it means the three
/// artifacts are one consistent set as far as a check without node state can
/// tell.
#[derive(Debug, Clone)]
pub struct ValidatedNetwork {
    manifest_bytes: Vec<u8>,
    manifest: NetworkManifestV1,
    reth_genesis: Vec<u8>,
    summit_genesis: Vec<u8>,
}

impl ValidatedNetwork {
    /// The manifest's bytes, to write verbatim: any re-serialization of the
    /// parsed value is a different document and a different network.
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    pub fn manifest(&self) -> &NetworkManifestV1 {
        &self.manifest
    }

    /// `SHA-256(manifest bytes)`.
    pub fn network_id(&self) -> NetworkId {
        NetworkId::from_manifest_bytes(&self.manifest_bytes)
    }

    /// The reth genesis JSON, to write verbatim.
    pub fn reth_genesis(&self) -> &[u8] {
        &self.reth_genesis
    }

    /// The summit genesis TOML, to write verbatim.
    pub fn summit_genesis(&self) -> &[u8] {
        &self.summit_genesis
    }
}

/// Why `[network]` is not one consistent artifact set, by the artifact that
/// fails.
///
/// Each level's message says only what failed at that level, and the cause is
/// its [`source`](std::error::Error::source): render the whole chain (anyhow's
/// `{:#}`/`{:?}`, or walking `source()`) to show it.
#[derive(Debug, thiserror::Error)]
pub enum InvalidNetwork {
    #[error("invalid network manifest")]
    Manifest(#[from] InvalidManifest),
    #[error("invalid reth genesis")]
    RethGenesis(#[from] InvalidRethGenesis),
    #[error("invalid summit genesis")]
    SummitGenesis(#[from] InvalidSummitGenesis),
}

/// Why `manifest_base64` is not a manifest.
#[derive(Debug, thiserror::Error)]
pub enum InvalidManifest {
    #[error("manifest_base64 is not valid base64")]
    Base64(#[source] base64::DecodeError),
    #[error(transparent)]
    Schema(#[from] ManifestError),
}

/// Why a reth genesis is not the one the manifest pins.
#[derive(Debug, thiserror::Error)]
pub enum InvalidRethGenesis {
    #[error("reth_genesis_base64 is not valid base64")]
    Base64(#[source] base64::DecodeError),
    #[error("not a genesis JSON object with integer config.chainId")]
    NotGenesis(#[source] serde_json::Error),
    #[error("config.chainId {found} does not match the manifest's eth.chain_id {expected}")]
    ChainIdMismatch { found: u64, expected: u64 },
}

/// Why a summit genesis is not the one the manifest pins.
#[derive(Debug, thiserror::Error)]
pub enum InvalidSummitGenesis {
    #[error("summit_genesis_base64 is not valid base64")]
    Base64(#[source] base64::DecodeError),
    #[error("not a summit genesis TOML document: not UTF-8")]
    NotUtf8(#[source] std::str::Utf8Error),
    #[error("not a summit genesis TOML document with a string namespace")]
    NotGenesis(#[source] toml::de::Error),
    #[error("namespace {found:?} does not match the manifest's summit.namespace {expected:?}")]
    NamespaceMismatch { found: String, expected: String },
}

impl InitConfig {
    /// Decode `[network]`'s three base64 artifacts and check them against one
    /// another: the manifest against the strict v1 schema, the reth genesis
    /// with [`check_reth_genesis`], the summit genesis with
    /// [`check_summit_genesis`].
    ///
    /// Not checked, because it needs node state: whether a node left with no
    /// peer in `bootnodes` holds the candidate the manifest pins. `tdx-init`
    /// reads the custodian's candidate file for that.
    pub fn validate(&self) -> Result<ValidatedNetwork, InvalidNetwork> {
        let network = &self.network;
        let manifest_bytes =
            decode_base64(&network.manifest_base64).map_err(InvalidManifest::Base64)?;
        let manifest =
            NetworkManifestV1::from_json_bytes(&manifest_bytes).map_err(InvalidManifest::from)?;
        let reth_genesis =
            decode_base64(&network.reth_genesis_base64).map_err(InvalidRethGenesis::Base64)?;
        check_reth_genesis(&manifest, &reth_genesis)?;
        let summit_genesis =
            decode_base64(&network.summit_genesis_base64).map_err(InvalidSummitGenesis::Base64)?;
        check_summit_genesis(&manifest, &summit_genesis)?;
        Ok(ValidatedNetwork {
            manifest_bytes,
            manifest,
            reth_genesis,
            summit_genesis,
        })
    }
}

/// The reth genesis is JSON whose `config.chainId` is the manifest's
/// `eth.chain_id`.
///
/// The manifest's `eth.genesis_hash = keccak(rlp(header))` pins the genesis
/// block (the header, and the alloc through the state root) but not the
/// file's `config` section, which lies outside the header. Only the
/// cross-checked field is parsed: the rest of the schema is reth's.
pub fn check_reth_genesis(
    manifest: &NetworkManifestV1,
    genesis: &[u8],
) -> Result<(), InvalidRethGenesis> {
    #[derive(Deserialize)]
    struct Genesis {
        config: Config,
    }
    #[derive(Deserialize)]
    struct Config {
        #[serde(rename = "chainId")]
        chain_id: u64,
    }

    let genesis: Genesis =
        serde_json::from_slice(genesis).map_err(InvalidRethGenesis::NotGenesis)?;
    if genesis.config.chain_id != manifest.eth.chain_id {
        return Err(InvalidRethGenesis::ChainIdMismatch {
            found: genesis.config.chain_id,
            expected: manifest.eth.chain_id,
        });
    }
    Ok(())
}

/// The summit genesis is TOML whose `namespace` is the manifest's
/// `summit.namespace`.
///
/// The manifest's `summit.genesis_config_digest` covers the consensus
/// parameters and every validator's keys and withdrawal credentials, but not
/// its IP, so a delivered copy with current validator IPs spliced in passes
/// this check as the assembled file does. Only the cross-checked field is
/// parsed: the rest of the schema is summit's.
pub fn check_summit_genesis(
    manifest: &NetworkManifestV1,
    genesis: &[u8],
) -> Result<(), InvalidSummitGenesis> {
    #[derive(Deserialize)]
    struct Genesis {
        namespace: String,
    }

    let text = std::str::from_utf8(genesis).map_err(InvalidSummitGenesis::NotUtf8)?;
    let genesis: Genesis = toml::from_str(text).map_err(InvalidSummitGenesis::NotGenesis)?;
    if genesis.namespace != manifest.summit.namespace {
        return Err(InvalidSummitGenesis::NamespaceMismatch {
            found: genesis.namespace,
            expected: manifest.summit.namespace.clone(),
        });
    }
    Ok(())
}

/// Decode a standard-alphabet base64 field, ignoring whitespace: transport
/// line wrapping (PEM-style) changes nothing about the decoded bytes.
fn decode_base64(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let stripped: String = encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD.decode(stripped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NetworkConfig, NodeConfig};

    /// The schema crate's golden fixture; that crate pins its network_id.
    const FIXTURE: &[u8] =
        include_bytes!("../../network-manifest/fixtures/network-manifest-v1.json");
    const FIXTURE_NETWORK_ID: &str =
        "0x0a6605bd97ed0e355059c052fb0e00323fd98a2b4081fed31f9db094ac06ba8a";
    /// The fixture's `eth.chain_id` and `summit.namespace`.
    const CHAIN_ID: u64 = 5124;
    const NAMESPACE: &str = "seismic-devnet-3";

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn reth_genesis(chain_id: u64) -> Vec<u8> {
        format!(r#"{{"config":{{"chainId":{chain_id},"mercuryTime":0}},"alloc":{{}}}}"#)
            .into_bytes()
    }

    fn summit_genesis(namespace: &str) -> Vec<u8> {
        format!("namespace = \"{namespace}\"\nchain_id = 5124\n\n[[validators]]\nbls_pubkey = \"0xab\"\n")
            .into_bytes()
    }

    fn manifest() -> NetworkManifestV1 {
        NetworkManifestV1::from_json_bytes(FIXTURE).unwrap()
    }

    /// A consistent config over the fixture manifest.
    fn config() -> InitConfig {
        InitConfig {
            network: NetworkConfig {
                manifest_base64: b64(FIXTURE),
                reth_genesis_base64: b64(&reth_genesis(CHAIN_ID)),
                summit_genesis_base64: b64(&summit_genesis(NAMESPACE)),
                bootnodes: vec![],
            },
            node: NodeConfig {
                external_ip: "203.0.113.7".parse().unwrap(),
            },
        }
    }

    #[test]
    fn a_consistent_config_decodes_to_the_verbatim_bytes() {
        let network = config().validate().unwrap();
        assert_eq!(network.manifest_bytes(), FIXTURE);
        assert_eq!(network.network_id().to_string(), FIXTURE_NETWORK_ID);
        assert_eq!(network.manifest().eth.chain_id, CHAIN_ID);
        assert_eq!(network.reth_genesis(), reth_genesis(CHAIN_ID));
        assert_eq!(network.summit_genesis(), summit_genesis(NAMESPACE));
    }

    #[test]
    fn wrapped_base64_decodes_to_the_same_bytes() {
        let wrap = |mut s: String| {
            s.insert(10, '\n');
            s.insert(20, ' ');
            s
        };
        let mut cfg = config();
        cfg.network.manifest_base64 = wrap(cfg.network.manifest_base64);
        cfg.network.reth_genesis_base64 = wrap(cfg.network.reth_genesis_base64);
        cfg.network.summit_genesis_base64 = wrap(cfg.network.summit_genesis_base64);
        let network = cfg.validate().unwrap();
        assert_eq!(network.manifest_bytes(), FIXTURE);
        assert_eq!(network.reth_genesis(), reth_genesis(CHAIN_ID));
        assert_eq!(network.summit_genesis(), summit_genesis(NAMESPACE));
    }

    /// A cosmetic edit still parses but is a different network.
    #[test]
    fn the_network_id_is_over_the_raw_bytes() {
        let mut cfg = config();
        cfg.network.manifest_base64 = b64(&[FIXTURE, b"\n"].concat());
        let network = cfg.validate().unwrap();
        assert_ne!(network.network_id().to_string(), FIXTURE_NETWORK_ID);
    }

    #[test]
    fn each_artifact_rejects_invalid_base64() {
        let mut cfg = config();
        cfg.network.manifest_base64 = "not-base64!!!".into();
        let err = cfg.validate().unwrap_err();
        assert!(
            matches!(err, InvalidNetwork::Manifest(InvalidManifest::Base64(_))),
            "{err:?}"
        );

        let mut cfg = config();
        cfg.network.reth_genesis_base64 = "not-base64!!!".into();
        let err = cfg.validate().unwrap_err();
        assert!(
            matches!(
                err,
                InvalidNetwork::RethGenesis(InvalidRethGenesis::Base64(_))
            ),
            "{err:?}"
        );

        let mut cfg = config();
        cfg.network.summit_genesis_base64 = "not-base64!!!".into();
        let err = cfg.validate().unwrap_err();
        assert!(
            matches!(
                err,
                InvalidNetwork::SummitGenesis(InvalidSummitGenesis::Base64(_))
            ),
            "{err:?}"
        );
    }

    /// Schema enforcement is the schema crate's, tested there; this pins only
    /// that its errors surface as a manifest failure.
    #[test]
    fn a_schema_error_is_a_manifest_failure() {
        let mut value: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
        value["tx_io_pk"] = "0x02ab".into();
        let mut cfg = config();
        cfg.network.manifest_base64 = b64(&serde_json::to_vec(&value).unwrap());
        let err = cfg.validate().unwrap_err();
        assert!(
            matches!(err, InvalidNetwork::Manifest(InvalidManifest::Schema(_))),
            "{err:?}"
        );
    }

    #[test]
    fn validate_runs_the_genesis_checks() {
        let mut cfg = config();
        cfg.network.reth_genesis_base64 = b64(&reth_genesis(CHAIN_ID + 1));
        let err = cfg.validate().unwrap_err();
        assert!(
            matches!(
                err,
                InvalidNetwork::RethGenesis(InvalidRethGenesis::ChainIdMismatch { .. })
            ),
            "{err:?}"
        );

        let mut cfg = config();
        cfg.network.summit_genesis_base64 = b64(&summit_genesis("other-net"));
        let err = cfg.validate().unwrap_err();
        assert!(
            matches!(
                err,
                InvalidNetwork::SummitGenesis(InvalidSummitGenesis::NamespaceMismatch { .. })
            ),
            "{err:?}"
        );
    }

    /// Each level says only what failed there, so the cause appears once in
    /// the chain rather than repeated at every level.
    #[test]
    fn the_message_names_the_artifact_and_the_cause_is_the_source() {
        let mut cfg = config();
        cfg.network.reth_genesis_base64 = b64(&reth_genesis(CHAIN_ID + 1));
        let err = cfg.validate().unwrap_err();
        assert_eq!(err.to_string(), "invalid reth genesis");
        assert_eq!(
            std::error::Error::source(&err).unwrap().to_string(),
            "config.chainId 5125 does not match the manifest's eth.chain_id 5124"
        );
    }

    #[test]
    fn the_reth_genesis_must_carry_the_manifests_chain_id() {
        let manifest = manifest();
        check_reth_genesis(&manifest, &reth_genesis(CHAIN_ID)).unwrap();

        let err = check_reth_genesis(&manifest, &reth_genesis(CHAIN_ID + 1)).unwrap_err();
        assert!(
            matches!(
                err,
                InvalidRethGenesis::ChainIdMismatch {
                    found: 5125,
                    expected: 5124
                }
            ),
            "{err:?}"
        );

        for not_a_genesis in [
            br#"{"alloc":{}}"#.as_slice(),
            br#"{"config":{"chainId":"5124"}}"#,
            b"{",
        ] {
            let err = check_reth_genesis(&manifest, not_a_genesis).unwrap_err();
            assert!(matches!(err, InvalidRethGenesis::NotGenesis(_)), "{err:?}");
        }
    }

    #[test]
    fn the_summit_genesis_must_carry_the_manifests_namespace() {
        let manifest = manifest();
        check_summit_genesis(&manifest, &summit_genesis(NAMESPACE)).unwrap();

        let err = check_summit_genesis(&manifest, &summit_genesis("other-net")).unwrap_err();
        assert!(
            matches!(
                &err,
                InvalidSummitGenesis::NamespaceMismatch { found, expected }
                    if found == "other-net" && expected == NAMESPACE
            ),
            "{err:?}"
        );

        let err = check_summit_genesis(&manifest, b"namespace = \"\xff\"\n").unwrap_err();
        assert!(matches!(err, InvalidSummitGenesis::NotUtf8(_)), "{err:?}");

        for not_a_genesis in [
            b"chain_id = 5124\n".as_slice(),
            b"namespace = 7\n",
            b"namespace = [",
            b"{\"namespace\": \"x\"",
        ] {
            let err = check_summit_genesis(&manifest, not_a_genesis).unwrap_err();
            assert!(
                matches!(err, InvalidSummitGenesis::NotGenesis(_)),
                "{err:?}"
            );
        }
    }
}
