#[cfg(test)]
use seismic_enclave::client::rpc::BuildableServer;
use seismic_enclave::client::EnclaveClient;
use seismic_enclave::client::ENCLAVE_DEFAULT_ENDPOINT_ADDR;
use seismic_enclave::get_unsecure_sample_secp256k1_pk;
use seismic_enclave::request_types::tx_io::*;
use seismic_enclave::rpc::EnclaveApiClient;
use seismic_enclave::MockEnclaveServer;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::thread::sleep;
use std::time::Duration;

fn get_random_port() -> u16 {
    TcpListener::bind("127.0.0.1:0") // 0 means OS assigns a free port
        .expect("Failed to bind to a port")
        .local_addr()
        .unwrap()
        .port()
}

async fn test_tx_io_encrypt_decrypt(client: &EnclaveClient) {
    // make the request struct
    let data_to_encrypt = vec![72, 101, 108, 108, 111];
    let mut nonce = vec![0u8; 4]; // 4 leading zeros
    nonce.extend_from_slice(&(12345678u64).to_be_bytes()); // Append the 8-byte u64
    let encryption_request = IoEncryptionRequest {
        key: get_unsecure_sample_secp256k1_pk(),
        data: data_to_encrypt.clone(),
        nonce: nonce.clone().into(),
    };

    // make the http request
    let encryption_response = client.encrypt(encryption_request).await.unwrap();

    // check the response
    assert!(!encryption_response.encrypted_data.is_empty());

    let decryption_request = IoDecryptionRequest {
        key: get_unsecure_sample_secp256k1_pk(),
        data: encryption_response.encrypted_data,
        nonce: nonce.into(),
    };

    let decryption_response = client.decrypt(decryption_request).await.unwrap();
    assert_eq!(decryption_response.decrypted_data, data_to_encrypt);
}

async fn test_health_check(client: &EnclaveClient) {
    let resposne = client.health_check().await.unwrap();
    assert_eq!(resposne, "OK");
}

async fn test_get_public_key(client: &EnclaveClient) {
    let res = client.get_public_key().await.unwrap();
    assert_eq!(res, get_unsecure_sample_secp256k1_pk());
}

async fn test_get_eph_rng_keypair(client: &EnclaveClient) {
    let res = client.get_eph_rng_keypair().await.unwrap();
    println!("eph_rng_keypair: {:?}", res);
}

#[tokio::test]
async fn test_server() {
    // spawn a seperate thread for the server, otherwise the test will hang
    let port = get_random_port();
    let addr = SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_ADDR, port));
    println!("addr: {:?}", addr);
    let _server_handle = MockEnclaveServer::new(addr).start().await.unwrap();
    sleep(Duration::from_secs(4));
    let client = EnclaveClient::new(format!("http://{}:{}", addr.ip(), addr.port()));
    println!("client: {:?}", client);

    test_health_check(&client).await;
    test_tx_io_encrypt_decrypt(&client).await;
    test_get_public_key(&client).await;
    test_get_eph_rng_keypair(&client).await;

    let client = EnclaveClient::new(format!("http://{}:{}", addr.ip(), addr.port()));

    let handle = tokio::spawn(async move {
        println!("client 2: {:?}", client);
        test_health_check(&client).await;
        test_tx_io_encrypt_decrypt(&client).await;
        test_get_public_key(&client).await;
        test_get_eph_rng_keypair(&client).await;
    });
    handle.await.unwrap();
}
