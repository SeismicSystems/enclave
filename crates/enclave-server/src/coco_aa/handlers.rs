use jsonrpsee::core::RpcResult;

use super::attest;
use seismic_enclave::request_types::coco_aa::*;
use seismic_enclave::rpc_bad_argument_error;

/// Handles attestation evidence request.
///
/// Attestation evidence is:
/// 1) The current state of the TEE, such as its RTMR measurements,
/// 2) The runtime data that is included in the request.
///     This can be up to 64 bytes, usually acting as a nonce to prevent replay
///     or the hash of some other data
/// 3) A signature of 1) and 2) above, which needs to be checked against
///     a registry of enclave public keys.
///     Intel maintains a pccs, and you can configure which service to use
///     by modifying /etc/sgx_default_qcnl.conf
///
/// See https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
/// Section 2.3.2 for more details
pub async fn attestation_get_evidence_handler(
    req: AttestationGetEvidenceRequest,
) -> RpcResult<AttestationGetEvidenceResponse> {
    // Get the evidence from the attestation agent
    let evidence = attest(req.runtime_data.as_slice())
        .await
        .map_err(|e| rpc_bad_argument_error(e))?;

    // Return the evidence as a response
    Ok(AttestationGetEvidenceResponse { evidence })
}

#[cfg(test)]
mod tests {
    use crate::{coco_aa::init_coco_aa, utils::test_utils::is_sudo};

    use super::*;

    use serial_test::serial;

    #[tokio::test]
    #[serial(attestation_agent)]
    async fn test_attestation_evidence_handler_valid_request_sample() {
        // NOTE: This test will run with the Sample TEE Type
        // because it doesn't run with sudo privileges

        init_coco_aa().expect("Failed to initialize AttestationAgent");

        // Mock a valid AttestationGetEvidenceRequest
        let runtime_data = "nonce".as_bytes(); // Example runtime data
        let evidence_request = AttestationGetEvidenceRequest {
            runtime_data: runtime_data.to_vec(),
        };

        // Call the handler
        let res = attestation_get_evidence_handler(evidence_request)
            .await
            .unwrap();

        // Ensure the response is not empty
        assert!(!res.evidence.is_empty());
    }

    #[tokio::test]
    #[serial(attestation_agent)]
    async fn test_attestation_evidence_handler_aztdxvtpm_runtime_data() {
        // handle set up permissions
        if !is_sudo() {
            eprintln!("test_eval_evidence_az_tdx: skipped (requires sudo privileges)");
            return;
        }

        init_coco_aa().expect("Failed to initialize AttestationAgent");

        // Make requests with different runtime data and see they are different
        let runtime_data_1 = "nonce1".as_bytes();
        let evidence_request_1 = AttestationGetEvidenceRequest {
            runtime_data: runtime_data_1.to_vec(),
        };

        let runtime_data_2 = "nonce2".as_bytes();
        let evidence_request_2 = AttestationGetEvidenceRequest {
            runtime_data: runtime_data_2.to_vec(),
        };

        let res_1 = attestation_get_evidence_handler(evidence_request_1)
            .await
            .unwrap();
        let res_2 = attestation_get_evidence_handler(evidence_request_2)
            .await
            .unwrap();

        assert_ne!(res_1.evidence, res_2.evidence);
    }
}
