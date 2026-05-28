use seismic_enclave_server::Args;

pub fn get_args(n: u16, genesis_node: bool, peers: Vec<String>) -> Args {
    let port = 7878 + n;
    Args {
        ip: "0.0.0.0".to_string(),
        port,
        genesis_node,
        peers,
        mock: false,
    }
}
