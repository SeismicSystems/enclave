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
//
// Important: Azure's raw TDX quote measurements primarily attest the Microsoft
// OpenHCL/OpenVMM paravisor TD, not Seismic's nested guest OS image. Production
// Azure guest attestation also needs vTPM AK/PCR quote + event-log verification
// or equivalent MAA JWT claim verification. The current HCL+TDX envelope is only
// a platform endorsement and protocol-binding primitive.
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
        // TODO(attestation): replace this placeholder with a protocol-bound value
        // (for example, a nonce/public-key/tx_io_pk binding). Azure's vTPM report-data
        // NV index is 64 bytes, so we may pass either a 32-byte digest or a full 64-byte
        // value. Seismic bindings should normally be 32-byte domain-separated hashes,
        // leaving the remaining capacity unused unless a protocol explicitly needs it.
        //
        // Azure TDX evidence is generated through the Azure vTPM/HCL path rather than
        // by writing directly to a native TDX quote device. The input written via
        // vtpm::get_report_with_report_data(input) is exposed in HCL runtime claims as
        // `user-data`; the TD report's reportdata contains hash(HCL runtime claims),
        // not `input` directly. Since IMDS quotes that TD report, verifiers must check:
        //   1. HCL `user-data` == expected Seismic protocol binding.
        //   2. quote.report_data[..32] == hcl_report.var_data_sha256().
        // See https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design
        // A fixture test should assert this on real Azure evidence.
        let report_data = [1u8; 32];

        // Get Azure HCL/vTPM report containing the caller-supplied report data.
        let hcl_report_bytes = vtpm::get_report_with_report_data(&report_data)?;
        let hcl_report = HclReport::new(hcl_report_bytes.clone())?;

        // Extract the unsigned TD report that Azure IMDS will convert into a DCAP quote.
        let unsigned_td_report: tdx::TdReport = hcl_report.try_into()?;

        // Ask Azure IMDS to produce the signed TDX quote.
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

    /// Verifies the current raw DCAP quote path.
    ///
    /// Azure caveat: this checks Intel DCAP collateral and current TDX fields
    /// only. It does not verify Seismic guest PCRs/event logs, so it is not a
    /// complete Azure CVM guest attestation verifier.
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
