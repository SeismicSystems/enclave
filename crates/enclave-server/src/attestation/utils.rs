use anyhow::{Result, anyhow};
use dcap_rs::types::quotes::QeReportCertData;
use dcap_rs::types::quotes::version_4::QuoteV4;
use dcap_rs::utils::cert::{get_x509_issuer_cn, parse_certchain, parse_pem};
use std::panic::{AssertUnwindSafe, catch_unwind};
use x509_parser::der_parser::Oid;
use x509_parser::der_parser::asn1_rs::{OctetString, Sequence, oid};
use x509_parser::prelude::*;

use crate::attestation::CA;

pub fn get_pck_fmspc_and_issuer(quote: &QuoteV4) -> Result<(String, CA)> {
    // dcap-rs exposes infallible parsers for the nested QE report/certificate
    // data. The quote is network input, so keep a panic boundary here even
    // after the structural checks in enclave-server's quote parser.
    catch_unwind(AssertUnwindSafe(|| {
        parse_pck_fmspc_and_issuer(&quote.signature.qe_cert_data.cert_data)
    }))
    .map_err(|_| anyhow!("attestation quote contains malformed certificate data"))?
}

fn parse_pck_fmspc_and_issuer(cert_data: &[u8]) -> Result<(String, CA)> {
    // QeReportCertData contains a 384-byte report, a 64-byte signature, a
    // two-byte auth-data length, and at least a six-byte CertData header.
    const MIN_QE_REPORT_CERT_DATA_LEN: usize = 384 + 64 + 2 + 6;
    if cert_data.len() < MIN_QE_REPORT_CERT_DATA_LEN {
        return Err(anyhow!(
            "QE report certification data is truncated: expected at least {MIN_QE_REPORT_CERT_DATA_LEN} bytes, got {}",
            cert_data.len()
        ));
    }

    let raw_cert_data = QeReportCertData::from_bytes(cert_data);

    let pem = parse_pem(&raw_cert_data.qe_cert_data.cert_data)
        .map_err(|_| anyhow!("failed to parse PCK certificate data"))?;
    // Cert Chain:
    // [0]: pck ->
    // [1]: pck ca ->
    // [2]: root ca
    let cert_chain = parse_certchain(&pem);
    let pck = cert_chain
        .first()
        .ok_or_else(|| anyhow!("PCK certificate chain is empty"))?;

    let pck_issuer = get_x509_issuer_cn(pck);

    let pck_ca = match pck_issuer.as_str() {
        "Intel SGX PCK Platform CA" => CA::PLATFORM,
        "Intel SGX PCK Processor CA" => CA::PROCESSOR,
        _ => return Err(anyhow!("unknown PCK issuer: {pck_issuer}")),
    };

    let fmspc_slice = extract_fmspc_from_extension(pck)?;
    let fmspc = hex::encode(fmspc_slice);
    Ok((fmspc, pck_ca))
}

pub fn extract_fmspc_from_extension<'a>(cert: &'a X509Certificate<'a>) -> Result<[u8; 6]> {
    let sgx_extensions_bytes = cert
        .get_extension_unique(&oid!(1.2.840.113741.1.13.1))
        .map_err(|_| anyhow!("failed to read SGX extension"))?
        .ok_or_else(|| anyhow!("PCK certificate is missing the SGX extension"))?
        .value;

    let (_, sgx_extensions) = Sequence::from_der(sgx_extensions_bytes)
        .map_err(|_| anyhow!("invalid SGX extension encoding"))?;

    let mut fmspc = [0; 6];
    let mut found = false;

    let mut i = sgx_extensions.content.as_ref();

    while !i.is_empty() {
        let (j, current_sequence) =
            Sequence::from_der(i).map_err(|_| anyhow!("invalid SGX extension entry encoding"))?;
        i = j;
        let (j, current_oid) = Oid::from_der(current_sequence.content.as_ref())
            .map_err(|_| anyhow!("invalid SGX extension OID encoding"))?;
        match current_oid.to_id_string().as_str() {
            "1.2.840.113741.1.13.1.4" => {
                let (k, fmspc_bytes) =
                    OctetString::from_der(j).map_err(|_| anyhow!("invalid FMSPC encoding"))?;
                if !k.is_empty() {
                    return Err(anyhow!("trailing bytes after FMSPC"));
                }
                let fmspc_bytes = fmspc_bytes.as_ref();
                if fmspc_bytes.len() != fmspc.len() {
                    return Err(anyhow!(
                        "invalid FMSPC length: expected {}, got {}",
                        fmspc.len(),
                        fmspc_bytes.len()
                    ));
                }
                fmspc.copy_from_slice(fmspc_bytes);
                found = true;
                break;
            }
            _ => continue,
        }
    }

    if !found {
        return Err(anyhow!("PCK certificate is missing the FMSPC extension"));
    }

    Ok(fmspc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcap_rs::types::quotes::version_4::QuoteSignatureDataV4;
    use dcap_rs::types::quotes::{
        CertData, QuoteHeader,
        body::{EnclaveReport, QuoteBody},
    };

    #[test]
    fn malformed_qe_report_cert_data_returns_error() {
        let result = catch_unwind(AssertUnwindSafe(|| parse_pck_fmspc_and_issuer(&[])));

        assert!(result.is_ok(), "malformed cert data must not panic");
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn malformed_nested_cert_lengths_are_caught_at_quote_boundary() {
        let mut cert_data = vec![0; 456];
        // Make the QeAuthData length point past the end of the quote. This is
        // exactly the kind of nested length that dcap-rs parses with a direct
        // slice and would otherwise panic on.
        cert_data[448..450].copy_from_slice(&u16::MAX.to_le_bytes());

        let quote = QuoteV4 {
            header: QuoteHeader {
                version: 4,
                att_key_type: 2,
                tee_type: 0,
                qe_svn: [0; 2],
                pce_svn: [0; 2],
                qe_vendor_id: [0; 16],
                user_data: [0; 20],
            },
            quote_body: QuoteBody::SGXQuoteBody(EnclaveReport::from_bytes(&[0; 384])),
            signature_len: 128,
            signature: QuoteSignatureDataV4 {
                quote_signature: [0; 64],
                ecdsa_attestation_key: [0; 64],
                qe_cert_data: CertData {
                    cert_data_type: 6,
                    cert_data_size: cert_data.len() as u32,
                    cert_data,
                },
            },
        };

        assert!(get_pck_fmspc_and_issuer(&quote).is_err());
    }
}
