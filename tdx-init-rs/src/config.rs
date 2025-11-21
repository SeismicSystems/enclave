use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitConfig {
    pub ssh_keys: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<DomainConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<ArgsConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<LogConfig>,
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
pub struct LogConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reth: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclave: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuksToken {
    #[serde(rename = "type")]
    pub token_type: String,
    pub keyslots: Vec<String>,
    pub user_data: HashMap<String, String>,
}

// Default arguments structured as individual components
#[derive(Debug, Clone)]
pub struct DefaultArgs {
    pub seismic_reth: RethDefaultArgs,
    pub summit: SummitDefaultArgs,
    pub enclave: EnclaveDefaultArgs,
}

#[derive(Debug, Clone)]
pub struct RethDefaultArgs {
    pub node_args: Vec<&'static str>,
    pub enclave_args: Vec<&'static str>,
    pub chain_args: Vec<&'static str>,
    pub datadir_args: Vec<&'static str>,
    pub http_args: Vec<&'static str>,
    pub ws_args: Vec<&'static str>,
    pub auth_args: Vec<&'static str>,
    pub log_args: Vec<&'static str>,
    pub metrics_args: Vec<&'static str>,
}

#[derive(Debug, Clone)]
pub struct SummitDefaultArgs {
    pub engine_args: Vec<&'static str>,
    pub genesis_args: Vec<&'static str>,
    pub store_args: Vec<&'static str>,
    pub key_args: Vec<&'static str>,
    pub port_args: Vec<&'static str>,
    pub log_args: Vec<&'static str>,
    pub db_args: Vec<&'static str>,
}

#[derive(Debug, Clone)]
pub struct EnclaveDefaultArgs {
    pub endpoint_args: Vec<&'static str>,
}

impl DefaultArgs {
    pub fn new() -> Self {
        Self {
            seismic_reth: RethDefaultArgs {
                node_args: vec!["node", "-vvv"],
                enclave_args: vec![
                    "--enclave.endpoint-addr",
                    "0.0.0.0",
                    "--enclave.endpoint-port",
                    "7878",
                ],
                chain_args: vec!["--chain", "/usr/share/seismic-reth/genesis.json", "--full"],
                datadir_args: vec!["--datadir", "/persistent/reth"],
                http_args: vec![
                    "--http",
                    "--http.addr",
                    "0.0.0.0",
                    "--http.port",
                    "8545",
                    "--http.api",
                    "eth,net,web3,trace,rpc,debug,txpool",
                ],
                ws_args: vec![
                    "--ws",
                    "--ws.addr",
                    "0.0.0.0",
                    "--ws.port",
                    "8546",
                    "--ws.api",
                    "eth,net,trace,web3,rpc,debug,txpool",
                ],
                auth_args: vec![
                    "--auth-ipc",
                    "--auth-ipc.path",
                    "/var/volatile/reth_engine_api.ipc",
                ],
                log_args: vec!["--log.stdout.format", "json", "--log.file.max-files", "0"],
                metrics_args: vec!["--metrics", "127.0.0.1:9001"],
            },
            summit: SummitDefaultArgs {
                engine_args: vec![
                    "run",
                    "--engine-ipc-path",
                    "/var/volatile/reth_engine_api.ipc",
                ],
                genesis_args: vec!["--genesis-path", "/persistent/summit/genesis.toml"],
                store_args: vec!["--store-path", "/persistent/summit/db"],
                key_args: vec!["--key-path", "/persistent/summit/keys/key.pem"],
                port_args: vec![
                    "--port",
                    "18551",
                    "--rpc-port",
                    "3030",
                    "--prom-port",
                    "9090",
                ],
                log_args: vec![],
                db_args: vec!["--db-prefix", "quarts"],
            },
            enclave: EnclaveDefaultArgs {
                endpoint_args: vec!["--ip", "0.0.0.0", "--port", "7878"],
            },
        }
    }

    pub fn get_all_reth_flags(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        flags.extend(&self.seismic_reth.node_args);
        flags.extend(&self.seismic_reth.enclave_args);
        flags.extend(&self.seismic_reth.chain_args);
        flags.extend(&self.seismic_reth.datadir_args);
        flags.extend(&self.seismic_reth.http_args);
        flags.extend(&self.seismic_reth.ws_args);
        flags.extend(&self.seismic_reth.auth_args);
        flags.extend(&self.seismic_reth.log_args);
        flags.extend(&self.seismic_reth.metrics_args);
        flags
    }

    pub fn get_all_summit_flags(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        flags.extend(&self.summit.engine_args);
        flags.extend(&self.summit.genesis_args);
        flags.extend(&self.summit.store_args);
        flags.extend(&self.summit.key_args);
        flags.extend(&self.summit.port_args);
        flags.extend(&self.summit.log_args);
        flags.extend(&self.summit.db_args);
        flags
    }

    pub fn get_reth_flag_names(&self) -> Vec<&'static str> {
        self.get_all_reth_flags()
            .into_iter()
            .filter(|arg| arg.starts_with("--"))
            .collect()
    }

    pub fn get_summit_flag_names(&self) -> Vec<&'static str> {
        self.get_all_summit_flags()
            .into_iter()
            .filter(|arg| arg.starts_with("--"))
            .collect()
    }

    pub fn get_all_enclave_flags(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        flags.extend(&self.enclave.endpoint_args);
        flags
    }

    pub fn get_enclave_flag_names(&self) -> Vec<&'static str> {
        self.get_all_enclave_flags()
            .into_iter()
            .filter(|arg| arg.starts_with("--"))
            .collect()
    }
}
