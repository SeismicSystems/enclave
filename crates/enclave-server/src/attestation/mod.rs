pub mod pccs;
pub mod upgrade_contract;
pub mod utils;

use anyhow::{Result, anyhow};
#[cfg(target_os = "linux")]
use az_tdx_vtpm::{hcl::HclReport, imds, tdx, vtpm};
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
    pccs: IntelPccs,
}

// Currently Azure-only. The vTPM-via-IMDS path is the canonical surface on Azure CVMs
// (paravisor-mediated TDX; /dev/tdx_guest is not exposed to the guest).
// TODO(samlaf): For GCP support — fully-enlightened TDX with /dev/tdx_guest
// or /sys/kernel/config/tsm/report. We'll need a cloud-detect step (IMDS probe) and
// a second `get_attestation_evidence_gcp()` arm.
impl AttestationAgent {
    pub fn new() -> Result<Self> {
        Ok(Self {
            pccs: IntelPccs::new(),
        })
    }

    pub fn get_attestation_evidence(&self) -> Result<AttestationGetEvidenceResponse> {
        self.get_attestation_evidence_tpm()
    }

    // Only this function (and its `az_tdx_vtpm` import above) is gated on Linux
    // — not the whole `attestation` module or `enclave-server` crate — so the
    // rest of the codebase remains buildable / IDE-navigable on macOS. CI runs
    // on Linux and exercises the gated body. See the matching `[target.'cfg(...)'.dependencies]`
    // comment in Cargo.toml for why the dep itself is Linux-only.
    #[cfg(target_os = "linux")]
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

    #[cfg(not(target_os = "linux"))]
    fn get_attestation_evidence_tpm(&self) -> Result<AttestationGetEvidenceResponse> {
        Err(anyhow!(
            "TPM attestation requires az-tdx-vtpm, which is only available on Linux"
        ))
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
