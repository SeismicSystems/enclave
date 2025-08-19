//! Attestation Verifier Policies and the PolicyFixture object
//! Useful for testing the attestation verifier

use anyhow::Result;
use attestation_service::config::Config;
use attestation_service::token::simple::{Configuration, SimpleAttestationTokenBroker};
use attestation_service::token::{AttestationTokenBroker, AttestationTokenConfig};
use attestation_service::AttestationService;
use base64::Engine;
use std::collections::HashMap;

pub(crate) const ALLOW_POLICY: &str = r#"
package policy

default allow = true
"#;

pub(crate) const DENY_POLICY: &str = r#"
package policy

default allow = false
"#;

// TODO: eval if we need 7 and 11. and/or anything else.
// See https://confidentialcontainers.org/blog/2024/03/01/building-trust-into-os-images-for-confidential-containers/
// This article is written by Magnus Kulke, a CoCo maintainer who works at Microsoft
// You do not check rtmr because azure does not load the kernel until after they would be set
pub(crate) const YOCTO_POLICY: &str = r#"
package policy

import rego.v1

default allow = false

allow if {
	input["aztdxvtpm.quote.body.mr_td"] == "bb379f8e734a755832509f61403f99db2258a70a01e1172a499d6d364101b0675455b4e372a35c1f006541f2de0d7154"
	input["aztdxvtpm.quote.body.mr_seam"] == "9790d89a10210ec6968a773cee2ca05b5aa97309f36727a968527be4606fc19e6f73acce350946c9d46a9bf7a63f8430"
	input["aztdxvtpm.tpm.pcr04"] == "fc846c8703feffa34e7c70cc62701f534abd3a59942a04a20081f0bff7cf182d"
}
"#;

pub(crate) struct PolicyFixture {
    pub policy_map: HashMap<String, String>,
}

impl Default for PolicyFixture {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyFixture {
    /// Creates a blank PolicyFixture
    /// Policies can then be added with `with_policy`
    pub(crate) fn new() -> Self {
        let policy_map = HashMap::new();
        Self { policy_map }
    }

    /// Creates a PolicyFixture with several policies useful for testing
    /// Not used in production, as we currently have no use case for blanket allow/deny policies
    pub(crate) fn all_policies() -> Self {
        let mut policy_map = HashMap::new();

        policy_map.insert(
            "allow".to_string(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ALLOW_POLICY),
        );

        policy_map.insert(
            "deny".to_string(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(DENY_POLICY),
        );

        policy_map.insert(
            "yocto".to_string(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(YOCTO_POLICY),
        );

        // for share_root, we allow all,
        // and then the key fields are checked against an on-chain contract
        policy_map.insert(
            "share_root".to_string(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ALLOW_POLICY),
        );

        Self { policy_map }
    }

    /// Add a custom policy to the fixture
    #[allow(dead_code)]
    pub(crate) fn with_policy(mut self, id: &str, content: &str) -> Self {
        self.policy_map.insert(id.to_string(), content.to_string());
        self
    }

    /// Configure the verifier with all policies in this fixture
    pub(crate) async fn configure_verifier<T>(&self, verifier: &mut AttestationService) -> Result<()>
    where
        T: AttestationTokenBroker + Send + Sync + 'static,
    {
        for (policy_id, policy_content) in &self.policy_map {
            verifier
                .set_policy(policy_id.clone(), policy_content.clone())
                .await?;
        }
        Ok(())
    }

    /// Get the content of a specific policy
    #[allow(dead_code)]
    pub(crate) fn get_policy_content(&self, policy_id: &str) -> Option<&String> {
        self.policy_map.get(policy_id)
    }

    /// Get all policy IDs
    #[allow(dead_code)]
    pub(crate) fn get_policy_ids(&self) -> Vec<String> {
        self.policy_map.keys().cloned().collect()
    }

    #[allow(dead_code)]
    pub(crate) fn encode_policy(&self, policy: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(policy)
    }
}

/// Install all of the policies we've defined
pub async fn install_all_policies() -> anyhow::Result<()> {
    let as_config = Config {
        attestation_token_broker: AttestationTokenConfig::Simple(Configuration::default()),
        ..Default::default()
    };
    let mut verifier = AttestationService::new(as_config).await.unwrap();
    let fixture = PolicyFixture::all_policies();
    fixture
        .configure_verifier::<SimpleAttestationTokenBroker>(&mut verifier)
        .await
        .unwrap();
    Ok(())
}
