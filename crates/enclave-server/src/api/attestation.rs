use log::error;
use jsonrpsee::core::{async_trait, RpcResult};

use crate::api::traits::{AttestationApi, RpcResult, rpc_bad_argument_error};
use crate::coco_aa::attest;
use seismic_enclave::coco_aa::{AttestationGetEvidenceRequest, AttestationGetEvidenceResponse};

/// Implementation of attestation API
pub struct AttestationService;

#[async_trait]
impl AttestationApi for AttestationService {
    async fn get_attestation_evidence(
        &self,
        req: AttestationGetEvidenceRequest,
    ) -> RpcResult<AttestationGetEvidenceResponse> {
        let evidence = match attest(req.runtime_data.as_slice()).await {
            Ok(evidence) => evidence,
            Err(e) => {
                error!("Failed to get attestation evidence: {}", e);
                return Err(rpc_bad_argument_error(e));
            }
        };
        
        Ok(AttestationGetEvidenceResponse { evidence })
    }

    pub async fn genesis_get_data_handler(
        kp: &dyn NetworkKeyProvider,
    ) -> RpcResult<GenesisDataResponse> {
        let io_pk = kp.get_tx_io_pk();
        let (genesis_data, evidence) = att_genesis_data(io_pk)
            .await
            .map_err(|e| rpc_bad_argument_error(e))?;

        // Return the evidence as a response
        Ok(GenesisDataResponse {
            data: genesis_data,
            evidence,
        })
    }

    pub async fn attestation_eval_evidence_handler(
        request: AttestationEvalEvidenceRequest,
    ) -> RpcResult<AttestationEvalEvidenceResponse> {
        // Convert the request's runtime data hash algorithm to the original enum
        let runtime_data: Option<OriginalData> = request.runtime_data.map(|data| data.into_original());
        let runtime_data_hash_algorithm: OriginalHashAlgorithm =
            match request.runtime_data_hash_algorithm {
                Some(alg) => alg.into_original(),
                None => OriginalHashAlgorithm::Sha256,
            };

        // Call the evaluate function of the attestation service
        // Gets back a b64 JWT web token of the form "header.claims.signature"
        let eval_result = eval_att_evidence(
            request.evidence,
            request.tee,
            runtime_data,
            runtime_data_hash_algorithm,
            None,                          // hardcoded because AzTdxVtpm doesn't support init data
            OriginalHashAlgorithm::Sha256, // dummy val to make this compile
            request.policy_ids,
        )
        .await;

        let as_token: String = match eval_result {
            Ok(as_token) => as_token,
            Err(e) => {
                error!("Failed to evaluate attestation evidence: {}", e);
                return Err(rpc_bad_evidence_error(e));
            }
        };

        let claims: ASCoreTokenClaims = match parse_as_token_claims(&as_token) {
            Ok(claims) => claims,
            Err(e) => {
                error!("Failed to parse AS token: {}", e);
                return Err(rpc_bad_argument_error(anyhow::anyhow!(
                    "Error while parsing AS token: {e}"
                )));
            }
        };

        Ok(AttestationEvalEvidenceResponse {
            eval: true,
            claims: Some(claims),
        })
    }
}
