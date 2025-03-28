// policy_test_utils.rs

use crate::{coco_as::policies::YOCTO_POLICY, verifier::DcapAttVerifier};
use anyhow::Result;
use std::collections::HashMap;

pub const ALLOW_POLICY: &str = r#"
package policy

default allow = true
"#;

pub const DENY_POLICY: &str = r#"
package policy

default allow = false
"#;

pub const YOCTO_POLICY: &str = r#"
package policy

import rego.v1

default allow = false

allow if {
	input["aztdxvtpm.quote.body.mr_td"] == "bb379f8e734a755832509f61403f99db2258a70a01e1172a499d6d364101b0675455b4e372a35c1f006541f2de0d7154"
	input["aztdxvtpm.quote.body.mr_seam"] == "9790d89a10210ec6968a773cee2ca05b5aa97309f36727a968527be4606fc19e6f73acce350946c9d46a9bf7a63f8430"
	input["aztdxvtpm.tpm.pcr04"] == "fc846c8703feffa34e7c70cc62701f534abd3a59942a04a20081f0bff7cf182d"
}
"#;

pub const YOCTO_POLICY_UPDATED: &str = r#"
package policy

import rego.v1

default allow = false

allow if {
	input["aztdxvtpm.quote.body.mr_td"] == "bb379f8e734a755832509f61403f99db2258a70a01e1172a499d6d364101b0675455b4e372a35c1f006541f2de0d7155"
	input["aztdxvtpm.quote.body.mr_seam"] == "9790d89a10210ec6968a773cee2ca05b5aa97309f36727a968527be4606fc19e6f73acce350946c9d46a9bf7a63f8431"
	input["aztdxvtpm.tpm.pcr04"] == "fc846c8703feffa34e7c70cc62701f534abd3a59942a04a20081f0bff7cf1822"
}
"#;

pub struct PolicyFixture {
    pub policy_map: HashMap<String, String>,
}

impl PolicyFixture {
    pub fn new() -> Self {
        let mut policy_map = HashMap::new();
        
        policy_map.insert(
            "allow".to_string(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ALLOW_POLICY.to_string()),
        );
        
        policy_map.insert(
            "deny".to_string(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(DENY_POLICY.to_string()),
        );
        
        policy_map.insert(
            "yocto".to_string(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(YOCTO_POLICY.to_string()),
        );
        
        // Add more policies as needed for your test suite
        
        Self { policy_map }
    }
    
    /// Add a custom policy to the fixture
    pub fn with_policy(mut self, id: &str, content: &str) -> Self {
        self.policy_map.insert(id.to_string(), content.to_string());
        self
    }
    
    /// Configure the verifier with all policies in this fixture
    pub async fn configure_verifier(&self, verifier: &DcapAttVerifier) -> Result<()> {
        for (policy_id, policy_content) in &self.policy_map {
            verifier
                .set_policy(policy_id.clone(), policy_content.clone())
                .await?;
        }
        Ok(())
    }
    
    /// Get the content of a specific policy
    pub fn get_policy_content(&self, policy_id: &str) -> Option<&String> {
        self.policy_map.get(policy_id)
    }
    
    /// Get all policy IDs
    pub fn get_policy_ids(&self) -> Vec<String> {
        self.policy_map.keys().cloned().collect()
    }

    pub fn encode_policy(&self, policy: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(policy)
    }
}

/// Helper function to quickly set up a verifier with default policies
pub async fn set_default_policies(verifier: &DcapAttVerifier) -> Result<PolicyFixture> {
    let fixture = PolicyFixture::new();
    fixture.configure_verifier(verifier).await?;
    Ok(fixture)
}
