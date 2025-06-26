// use seismic_enclave::auth::JwtSecret;
use attestation_service::token::simple;
use seismic_enclave::client::rpc::BuildableServer;
use seismic_enclave::client::{EnclaveClient, EnclaveClientBuilder, ENCLAVE_DEFAULT_ENDPOINT_IP};
use seismic_enclave::request_types::AttestationGetEvidenceRequest;
use seismic_enclave::request_types::GetPurposeKeysRequest;
use seismic_enclave::rpc::EnclaveApiClient;
use seismic_enclave_server::attestation::SeismicAttestationAgent;
use seismic_enclave_server::key_manager::{KeyManager, KeyManagerBuilder};
use seismic_enclave_server::server::{init_tracing, EnclaveServer};

use serial_test::serial;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::thread::sleep;
use std::time::Duration;

pub fn is_sudo() -> bool {
    use std::process::Command;

    // Run the "id -u" command to check the user ID
    let output = Command::new("id")
        .arg("-u")
        .output()
        .expect("Failed to execute id command");

    // Convert the output to a string and trim any whitespace
    let user_id = String::from_utf8(output.stdout).unwrap().trim().to_string();

    // Check if the user ID is 0 (which means the user is root)
    user_id == "0"
}

pub fn get_random_port() -> u16 {
    TcpListener::bind("127.0.0.1:0") // 0 means OS assigns a free port
        .expect("Failed to bind to a port")
        .local_addr()
        .unwrap()
        .port()
}

async fn test_get_purpose_keys(client: &EnclaveClient) {
    client
        .get_purpose_keys(GetPurposeKeysRequest { epoch: 0 })
        .await
        .unwrap();
}

async fn test_health_check(client: &EnclaveClient) {
    let response = client.health_check().await.unwrap();
    assert_eq!(response, "OK");
}

async fn test_attestation_get_evidence(client: &EnclaveClient) {
    let runtime_data = "nonce".as_bytes(); // Example runtime data
    let evidence_request = AttestationGetEvidenceRequest {
        runtime_data: runtime_data.to_vec(),
    };

    // Call the handler
    let res = client
        .get_attestation_evidence(evidence_request)
        .await
        .unwrap();

    // Ensure the response is not empty
    assert!(!res.evidence.is_empty());
}

async fn test_attestation_eval_evidence(client: &EnclaveClient) {
    // Mock a valid AttestationEvalEvidenceRequest
    let eval_request = seismic_enclave_server::utils::test_utils::pub_key_eval_request();

    let response = client
        .eval_attestation_evidence(eval_request)
        .await
        .unwrap();

    assert!(response.claims.is_some());
}

// async fn test_genesis_get_data(client: &EnclaveClient) {
//     let response = client.get_genesis_data().await.unwrap();
//     assert!(!response.evidence.is_empty());
// }

// async fn test_misconfigured_auth_secret(ip: IpAddr, port: u16) {
//     let rand_auth_secret = JwtSecret::random();
//     let client = EnclaveClientBuilder::new()
//         .auth_secret(rand_auth_secret)
//         .ip(ip.to_string())
//         .port(port)
//         .timeout(Duration::from_secs(5))
//         .build()
//         .map_err(|e| {
//             anyhow!(
//                 "test_misconfigured_auth_secret Failed to build client: {:?}",
//                 e
//             )
//         })
//         .unwrap();
//     let response = client.health_check().await;
//     assert!(
//         response.is_err(),
//         "client should not be able to connect to server with wrong auth secret"
//     );
// }

#[tokio::test]
#[serial(attestation_agent, attestation_service)]
async fn test_server_requests() {
    init_tracing();
    // handle set up permissions
    if !is_sudo() {
        tracing::error!("test_server_requests: skipped (requires sudo privileges)");
        return;
    }

    // spawn a seperate thread for the server, otherwise the test will hang
    let port = get_random_port(); // rand port for test parallelization
    let addr = SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_IP, port));
    let kp = KeyManagerBuilder::build_mock().unwrap();

    let token_broker_config = attestation_service::token::AttestationTokenConfig::Simple(
        simple::Configuration::default(),
    );
    let mut att_serv_config: attestation_service::config::Config = Default::default();
    att_serv_config.attestation_token_broker = token_broker_config;

    let seismic_attestation_agent = SeismicAttestationAgent::new(None, att_serv_config).await;
    // let auth_secret = JwtSecret::random();
    let _server_handle = EnclaveServer::<KeyManager>::new(
        addr,
        kp,
        seismic_attestation_agent,
        // auth_secret,
    )
    .await
    .unwrap()
    .start()
    .await
    .unwrap();
    sleep(Duration::from_secs(4));

    let client = EnclaveClientBuilder::new()
        // .auth_secret(auth_secret)
        .ip(ENCLAVE_DEFAULT_ENDPOINT_IP.to_string())
        .port(port)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    client.boot_genesis().await.unwrap();
    client.complete_boot().await.unwrap();

    test_health_check(&client).await;
    test_get_purpose_keys(&client).await;
    test_attestation_get_evidence(&client).await;
    test_attestation_eval_evidence(&client).await;
    // test_genesis_get_data(&client).await;
    // test_misconfigured_auth_secret(addr.ip(), addr.port()).await;
}
