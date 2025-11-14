use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitConfig {
    pub ssh_keys: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<DomainConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<ArgsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainConfig {
    pub email: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclave: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reth: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuksToken {
    #[serde(rename = "type")]
    pub token_type: String,
    pub keyslots: Vec<String>,
    pub user_data: HashMap<String, String>,
}
