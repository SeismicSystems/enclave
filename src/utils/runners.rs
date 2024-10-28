use crate::genesis::structs::GenesisData;
use crate::utils::tdx_evidence_helpers::get_tdx_evidence_claims;
use sha2::Digest;
use sha2::Sha256;
#[allow(dead_code)]
#[allow(unused_imports)]

/// This file has cargo tests so I can
/// one click run them and see the output
/// They are for dev convenience only
use std::str::FromStr;

#[test]
#[ignore]
fn run_get_tdx_evidence_claims() -> Result<(), anyhow::Error> {
    // let path = "./src/coco_as/examples/yocto_20241023223507.txt";
    let path = "./src/coco_as/examples/yocto_20241025193121.txt";
    let tdx_evidence: Vec<u8> = crate::utils::test_utils::read_vector_txt(path.to_string())?;

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

    let genesis_data_bytes = genesis_data.to_bytes();
    let hash_bytes: [u8; 32] = Sha256::digest(genesis_data_bytes).into();
    println!("{:?}", hash_bytes);

    Ok(())
}
