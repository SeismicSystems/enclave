pub mod pccs;
pub mod upgrade_contract;
pub mod utils;

use anyhow::{Result, anyhow};
use az_tdx_vtpm::{hcl::HclReport, imds, tdx, vtpm};
use coco_provider::{coco::CocoDeviceType, get_coco_provider};
use dcap_rs::{types::quotes::version_4::QuoteV4, utils::quotes::version_4::verify_quote_dcapv4};
use seismic_enclave::AttestationGetEvidenceResponse;

use crate::attestation::{
    pccs::{IntelPccs, PccsProvider},
    upgrade_contract::verify_measurements_against_contract,
};

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum CA {
    PROCESSOR,
    PLATFORM,
    __Invalid,
}

pub struct AttestationAgent {
    provider: CocoDeviceType,
    pccs: IntelPccs,
}

impl AttestationAgent {
    pub fn new() -> Result<Self> {
        let provider = get_coco_provider()?;
        Ok(Self {
            provider: provider.device_type,
            pccs: IntelPccs::new(),
        })
    }

    pub fn get_attestation_evidence(&self) -> Result<AttestationGetEvidenceResponse> {
        match self.provider {
            // Azure and other TDX cloud providers use TPM
            CocoDeviceType::Tpm => self.get_attestation_evidence_tpm(),
            _ => self.get_attestation_evidence_tpm(), // todo: For some reason on Azure Ubuntu CVM it is going to Mock device type even when the tpm is available
        }
    }

    fn get_attestation_evidence_tpm(&self) -> Result<AttestationGetEvidenceResponse> {
        // todo this will be included in the quote, placeholding this for now we probably want our public key or a nonce here instead
        let report_data = [1u8; 32];

        // Get Unsigned td report
        let hcl_report_bytes = vtpm::get_report_with_report_data(&report_data)?;
        let hcl_report = HclReport::new(hcl_report_bytes.clone())?;

        // get the unsigned td report
        let unsigned_td_report: tdx::TdReport = hcl_report.try_into()?;

        // send td report to the imds to be signed
        let signed_td_report_bytes = imds::get_td_quote(&unsigned_td_report).unwrap();

        // let quote = QuoteV4::from_bytes(&signed_td_report_bytes);
        Ok(AttestationGetEvidenceResponse {
            hcl_report: hcl_report_bytes,
            quote: signed_td_report_bytes,
        })
    }

    pub async fn verify_attestation_report(&self, quote: QuoteV4) -> Result<()> {
        let collaterals = self.pccs.get_collateral(&quote).await?;
        let current_time = chrono::Utc::now().timestamp() as u64;

        match std::panic::catch_unwind(|| verify_quote_dcapv4(&quote, &collaterals, current_time)) {
            Ok(_) => {
                verify_measurements_against_contract(&quote).await?;
                Ok(())
            } // todo actually respond with something
            Err(e) => Err(anyhow!("DCAP Error: {:?}", e)),
        }
    }
}
