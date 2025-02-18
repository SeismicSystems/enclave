#[cfg(test)]
use jsonrpsee::http_client::HttpClient;
use kbs_types::Tee;
use secp256k1::PublicKey;
use seismic_enclave::coco_aa::AttestationGetEvidenceRequest;
use seismic_enclave::coco_as::AttestationEvalEvidenceRequest;
use seismic_enclave::coco_as::Data;
use seismic_enclave::coco_as::HashAlgorithm;
use seismic_enclave::request_types::tx_io::*;
use seismic_enclave::rpc::EnclaveApiClient;
use seismic_enclave::signing::Secp256k1SignRequest;
use seismic_enclave::signing::Secp256k1VerifyRequest;
use seismic_enclave_server::server::start_rpc_server;
use seismic_enclave_server::server::TEE_DEFAULT_ENDPOINT_ADDR;
use seismic_enclave_server::utils::test_utils::is_sudo;
use serial_test::serial;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;

fn get_random_port() -> u16 {
    TcpListener::bind("127.0.0.1:0") // 0 means OS assigns a free port
        .expect("Failed to bind to a port")
        .local_addr()
        .unwrap()
        .port()
}

async fn test_tx_io_encrypt_decrypt(client: &HttpClient) {
    // make the request struct
    let data_to_encrypt = vec![72, 101, 108, 108, 111];
    let mut nonce = vec![0u8; 4]; // 4 leading zeros
    nonce.extend_from_slice(&(12345678u64).to_be_bytes()); // Append the 8-byte u64
    let encryption_request = IoEncryptionRequest {
        key: PublicKey::from_str(
            "03e31e68908a6404a128904579c677534d19d0e5db80c7d9cf4de6b4b7fe0518bd",
        )
        .unwrap(),
        data: data_to_encrypt.clone(),
        nonce: nonce.clone().into(),
    };

    // make the http request
    let encryption_response = client.tx_io_encrypt(encryption_request).await.unwrap();

    // check the response
    assert!(!encryption_response.encrypted_data.is_empty());

    let decryption_request = IoDecryptionRequest {
        key: PublicKey::from_str(
            "03e31e68908a6404a128904579c677534d19d0e5db80c7d9cf4de6b4b7fe0518bd",
        )
        .unwrap(),
        data: encryption_response.encrypted_data,
        nonce: nonce.into(),
    };

    let decryption_response = client.tx_io_decrypt(decryption_request).await.unwrap();
    assert_eq!(decryption_response.decrypted_data, data_to_encrypt);
}

async fn test_health_check(client: &HttpClient) {
    let resposne = client.health_check().await.unwrap();
    assert_eq!(resposne, "OK");
}

async fn test_genesis_get_data(client: &HttpClient) {
    let resposne = client.genesis_get_data().await.unwrap();
    assert!(!resposne.evidence.is_empty());
}

async fn test_attestation_get_evidence(client: &HttpClient) {
    let runtime_data = "nonce".as_bytes(); // Example runtime data
    let evidence_request = AttestationGetEvidenceRequest {
        runtime_data: runtime_data.to_vec(),
    };

    // Call the handler
    let res = client
        .attestation_get_evidence(evidence_request)
        .await
        .unwrap();

    // Ensure the response is not empty
    assert!(!res.evidence.is_empty());
}

async fn test_attestation_eval_evidence(client: &HttpClient) {
    // Mock a valid AttestationEvalEvidenceRequest
    let eval_request = AttestationEvalEvidenceRequest {
        evidence: vec![
            123, 34, 115, 118, 110, 34, 58, 34, 49, 34, 44, 34, 114, 101, 112, 111, 114, 116, 95,
            100, 97, 116, 97, 34, 58, 34, 98, 109, 57, 117, 89, 50, 85, 61, 34, 125,
        ], // Example evidence data
        tee: Tee::Sample,
        runtime_data: Some(Data::Raw("nonce".as_bytes().to_vec())), // Example runtime data
        runtime_data_hash_algorithm: Some(HashAlgorithm::Sha256),
        policy_ids: vec!["allow".to_string()],
    };

    let resposne = client
        .attestation_eval_evidence(eval_request)
        .await
        .unwrap();

    assert!(resposne.eval);
}

async fn test_secp256k1_sign_verify(client: &HttpClient) {
    // Prepare sign request to get a valid signature
    let msg_to_sign: Vec<u8> = vec![84, 101, 115, 116, 32, 77, 101, 115, 115, 97, 103, 101]; // "Test Message"
    let sign_request = Secp256k1SignRequest {
        msg: msg_to_sign.clone(),
    };
    let res = client.secp256k1_sign(sign_request).await.unwrap();

    // Prepare verify request body
    let verify_request = Secp256k1VerifyRequest {
        msg: msg_to_sign,
        sig: res.sig,
    };

    let res = client.secp256k1_verify(verify_request).await.unwrap();
    assert_eq!(res.verified, true);
}

#[tokio::test]
#[serial(attestation_agent, attestation_service)]
async fn test_server() {
    // handle set up permissions
    if !is_sudo() {
        eprintln!("test_server: skipped (requires sudo privileges)");
        return;
    }

    // spawn a seperate thread for the server, otherwise the test will hang
    let port = get_random_port();
    let addr = SocketAddr::from((TEE_DEFAULT_ENDPOINT_ADDR, port));
    let _server_handle = start_rpc_server(addr).await.unwrap();
    sleep(Duration::from_secs(4));
    let client = jsonrpsee::http_client::HttpClientBuilder::default()
        .build(format!("http://{}:{}", addr.ip(), addr.port()))
        .unwrap();

    test_health_check(&client).await;
    test_genesis_get_data(&client).await;
    test_tx_io_encrypt_decrypt(&client).await;
    test_attestation_get_evidence(&client).await;
    test_attestation_eval_evidence(&client).await;
    test_secp256k1_sign_verify(&client).await;
}
