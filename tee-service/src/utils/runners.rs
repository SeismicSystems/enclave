//! This file has cargo tests so I can
//! one click run them and see the output
//! They are for dev convenience only

use super::tdx_evidence_helpers::get_tdx_evidence_claims;
use anyhow::Ok;
use attestation_service::config::Config;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::Digest;
use sha2::Sha256;
use std::str::FromStr;
use tee_service_api::get_sample_rsa;
use tee_service_api::request_types::genesis::GenesisData;

#[allow(dead_code)]
#[allow(unused_imports)]
use tee_service_api::request_types::*;

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
        io_pk: secp256k1::PublicKey::from_str(
            "028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0",
        )
        .unwrap(),
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

#[test]
#[ignore]
fn see_rsa_keypair() -> Result<(), anyhow::Error> {
    let rsa = get_sample_rsa();
    let public_key_pem = rsa.public_key_to_pem().unwrap();
    let pk_hash: [u8; 32] = Sha256::digest(public_key_pem.as_slice()).into();

    println!("public key: {:?}", public_key_pem);
    println!("public key len: {:?}", public_key_pem.len());
    println!("pk hash{:?}", pk_hash);

    // let private_key_pem = rsa.private_key_to_pem().unwrap();
    // println!("{:?}", private_key_pem);
    Ok(())
}
