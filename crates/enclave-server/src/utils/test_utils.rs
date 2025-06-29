use seismic_enclave::get_unsecure_sample_secp256k1_pk;
use seismic_enclave::request_types::AttestationEvalEvidenceRequest;
use std::fs::File;
use std::io::{self, Read};
use std::net::TcpListener;

/// Checks if the current user has root (sudo) privileges.
///
/// This function runs the `id -u` command, which returns the current user's ID.
/// In Unix-like systems, the user ID of the root user is `0`. The function checks
/// if the output of the `id -u` command is `"0"`, indicating that the user is running
/// as root (with sudo privileges).
///
/// # Returns
///
/// - `true`: If the user has root privileges (user ID is `0`).
/// - `false`: If the user does not have root privileges.
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

/// reads a vector of the form [1, 2, 3, 4] from a txt file
/// It takes the file path as a String and returns a Vec<u8>
pub fn read_vector_txt(path: String) -> io::Result<Vec<u8>> {
    // Open the file
    let mut file = File::open(path)?;

    // Read the file contents into a string
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    // Remove the brackets and split the string into individual numbers
    let trimmed = contents.trim_matches(|c| c == '[' || c == ']').trim();

    // Convert the split numbers into a vector of u8
    let vec: Vec<u8> = trimmed
        .split(',')
        .map(|s| s.trim().parse().expect("Failed to parse number"))
        .collect();

    // Return the vector
    Ok(vec)
}

pub fn get_random_port() -> u16 {
    TcpListener::bind("127.0.0.1:0") // 0 means OS assigns a free port
        .expect("Failed to bind to a port")
        .local_addr()
        .unwrap()
        .port()
}

/// A mock attestation evaluation request for testing
/// Based on a saved sample attestation file
/// attests to a public secp256k1 key from an AzTdxVtpm machine
pub fn pub_key_eval_request() -> AttestationEvalEvidenceRequest {
    use seismic_enclave::request_types::{Data, HashAlgorithm};
    let evidence = read_vector_txt("../../examples/az_tdx_key_att.txt".to_string()).unwrap();
    let req = AttestationEvalEvidenceRequest {
        evidence,
        tee: kbs_types::Tee::AzTdxVtpm,
        runtime_data: Some(Data::Raw(
            get_unsecure_sample_secp256k1_pk().serialize().to_vec(),
        )),
        runtime_data_hash_algorithm: Some(HashAlgorithm::Sha256),
        policy_ids: vec!["allow".to_string()],
    };
    // println!("pub_key_eval_request: {:?}", req);
    req
}
