use seismic_attestation_service::Args;
use seismic_custodian_ipc::server::{MethodAcl, bind, serve};
use seismic_key_custodian_host::{dispatch::dispatch, state::CustodianState};
use std::path::{Path, PathBuf};

pub fn get_args(n: u16, peers: Vec<String>, custodian_socket: PathBuf) -> Args {
    let port = 7878 + n;
    Args {
        ip: "0.0.0.0".to_string(),
        port,
        peers,
        custodian_socket,
        mock: false,
    }
}

/// Serve `state` over a custodian socket from a dedicated thread — the same
/// transport and dispatch the standalone `seismic-key-custodian` binary runs.
pub fn spawn_custodian(state: CustodianState, socket: &Path) {
    let listener = bind(socket).expect("bind custodian socket");
    std::thread::spawn(move || {
        serve(listener, MethodAcl::own_uid_only(), move |request| {
            dispatch(&state, request)
        })
    });
}
