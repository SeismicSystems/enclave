//! This file has cargo tests so I can
//! one click run them and see the output
//! They are for dev convenience only
//! and should be ignored in automated testing workflows

use crate::attestation::seismic_aa_mock;
use crate::attestation::SeismicAttestationAgent;
use attestation_agent::AttestationAPIs;

use anyhow::Ok;
use attestation_service::config::Config;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use seismic_enclave::get_unsecure_sample_secp256k1_pk;
use sha2::Digest;
use sha2::Sha256;
use std::str::FromStr;

#[test]
#[ignore]
pub fn print_active_feature() {
    #[cfg(feature = "az-tdx-vtpm-attester")]
    {
        println!("az-tdx-vtpm-attester enabled");
    }

    #[cfg(not(feature = "az-tdx-vtpm-attester"))]
    {
        println!("az-tdx-vtpm-attester not enabled");
    }
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

#[cfg(feature = "az-tdx-vtpm-attester")]
#[cfg(test)]
mod attester_tests {
    use super::*;
    use crate::utils::tdx_evidence_helpers::get_tdx_evidence_claims;
    use crate::utils::test_utils::read_vector_txt;

    #[tokio::test]
    #[ignore]
    async fn run_create_tdx_evidence() -> Result<(), anyhow::Error> {
        let unsecure_secp256k1_pk = get_unsecure_sample_secp256k1_pk();
        let runtime_data = unsecure_secp256k1_pk.serialize().to_vec();
        let saa = seismic_aa_mock().await;
        let tdx_evidence = saa.get_evidence(&runtime_data.to_vec()).await?;
        print_active_feature();
        println!("{:?}", saa.get_tee_type());
        println!("{:?}", tdx_evidence);
        assert!(false); // so I can see the print statement
        Ok(())
    }

    #[test]
    #[ignore]
    fn run_get_tdx_evidence_claims() -> Result<(), anyhow::Error> {
        let path = "./src/coco_as/examples/yocto_20241025193121.txt"; // Note this file has moved
        let tdx_evidence: Vec<u8> = read_vector_txt(path.to_string())?;

        get_tdx_evidence_claims(tdx_evidence)?;

        Ok(())
    }
}
