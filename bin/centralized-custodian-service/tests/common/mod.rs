#![allow(dead_code)]

use seismic_centralized_custodian_service::{
    council::CouncilHandler, observer_serving::ObserverServing, state::CentralizedCustodianState,
};
use seismic_council_delivery::{
    SignedDeliveryEnvelope, address_from_pubkey, network_id_from_chain_id, seal_delivery,
};
use seismic_custodian::Custodian;
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

pub const CHAIN_ID: u64 = 5124;
pub const ROOT: [u8; 32] = [7; 32];
pub const SEED: [u8; 32] = [1; 32];
pub const EPOCH_ROOT: [u8; 32] = [0x42; 32];

pub fn council_key() -> secp256k1::SecretKey {
    secp256k1::SecretKey::from_byte_array(&[0x77; 32]).unwrap()
}

pub fn state(dir: &Path) -> Arc<CentralizedCustodianState> {
    let public = council_key().public_key(&secp256k1::Secp256k1::new());
    Arc::new(
        CentralizedCustodianState::new(
            Custodian::new(ROOT),
            dir.join("deliveries"),
            address_from_pubkey(&public),
            network_id_from_chain_id(CHAIN_ID),
        )
        .unwrap(),
    )
}

pub fn envelope(epoch: u64) -> SignedDeliveryEnvelope {
    seal_delivery(
        &council_key(),
        &network_id_from_chain_id(CHAIN_ID),
        epoch,
        &EPOCH_ROOT,
    )
}

pub fn serving(dir: &Path) -> Arc<ObserverServing> {
    let path = dir.join("summit");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("node_key.pem"), hex::encode(SEED)).unwrap();
    Arc::new(ObserverServing::load(&path, CHAIN_ID, ROOT).unwrap())
}

/// Finite-lifetime real HTTP handler fixture; no leaked server threads.
pub struct HttpServer {
    pub base: String,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl HttpServer {
    pub fn new(handler: CouncilHandler) -> Self {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let base = format!("http://{}", server.server_addr());
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let worker = thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                if let Some(request) = server.recv_timeout(Duration::from_millis(50)).unwrap() {
                    handler.handle_http(request);
                }
            }
        });
        Self {
            base,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}
