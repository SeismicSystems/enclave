//! This file has cargo tests so I can
//! one click run them and see the output
//! They are for dev convenience only
//! and should be ignored in automated testing workflows

use super::tdx_evidence_helpers::get_tdx_evidence_claims;
use anyhow::Ok;
use attestation_service::config::Config;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use seismic_enclave::get_unsecure_sample_secp256k1_pk;
use seismic_enclave::request_types::genesis::GenesisData;
use sha2::Digest;
use sha2::Sha256;
use std::str::FromStr;

#[allow(dead_code)]
#[allow(unused_imports)]
use seismic_enclave::request_types::*;

#[test]
#[ignore]
fn run_get_tdx_evidence_claims() -> Result<(), anyhow::Error> {
    // let path = "./src/coco_as/examples/yocto_20241023223507.txt";
    let path = "./src/coco_as/examples/yocto_20241025193121.txt";
    let tdx_evidence: Vec<u8> = super::test_utils::read_vector_txt(path.to_string())?;

    get_tdx_evidence_claims(tdx_evidence)?;

    Ok(())
}

#[test]
#[ignore]
fn run_hash_genesis_data() -> Result<(), anyhow::Error> {
    let genesis_data = GenesisData {
        io_pk: get_unsecure_sample_secp256k1_pk(),
    };

    let genesis_data_bytes = genesis_data.to_bytes()?;
    let hash_bytes: [u8; 32] = Sha256::digest(genesis_data_bytes).into();
    println!("{:?}", hash_bytes);

    Ok(())
}

#[test]
#[ignore]
fn see_as_token() -> Result<(), anyhow::Error> {
    let as_token = std::fs::read_to_string("./src/coco_as/examples/as_token.txt").unwrap();
    let parts: Vec<&str> = as_token.splitn(3, '.').collect();
    let claims_b64 = parts[1];
    let claims_decoded_bytes = URL_SAFE_NO_PAD.decode(claims_b64)?;
    let claims_decoded_string = String::from_utf8(claims_decoded_bytes)?;
    let claims_pretty_str = serde_json::to_string_pretty(&claims_decoded_string)?;
    println!("{claims_pretty_str}");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn see_default_config() {
    let config = Config::default();
    println!("{:?}", config);
}

//#[tokio::test]
//#[ignore]
//async fn get_mrtd() {
//    use alloy_primitives::Bytes;
//    let rootfs_hash = Bytes::from(vec![0x00; 32]);
//    let mrtd = Bytes::from(vec![0x00; 48]);
//    let rtmr0 = Bytes::from(vec![0x00; 48]);
//    let rtmr3 = Bytes::from(vec![0x00; 48]);
//
//    let _result = check_operator(rootfs_hash, mrtd, rtmr0, rtmr3)
//        .await
//        .unwrap();
//}

//#[tokio::test(flavor = "multi_thread")]
//async fn run_client_ping() {
//    use seismic_enclave::rpc::SyncEnclaveApiClient;
//    use seismic_enclave::snapshot::RestoreFromEncryptedSnapshotRequest;
//    use seismic_enclave::EnclaveClient;
//
//    let url = "http://yocto-1.seismicdev.net:7878";
//    // let url = "http://127.0.0.1:7878";
//    let client = EnclaveClient::new(url);
//
//    // // health check
//    // let resp = client.health_check().unwrap();
//    // println!("resp: {:?}", resp);
//}
