use std::panic;
use serde_json::Value::String;
use crate::{qe_identity, Quote, quote, QuoteCollateral, tcb};
use der::{Decode, Enumerated, Error, ErrorKind, Sequence};

use chrono::{DateTime, FixedOffset, Timelike, TimeZone};

// #define SUPPLEMENTAL_DATA_VERSION 3
// #define QVE_COLLATERAL_VERSION1 0x1
// #define QVE_COLLATERAL_VERSION3 0x3
// #define QVE_COLLATERAL_VERSOIN31 0x00010003
// #define QVE_COLLATERAL_VERSION4 0x4
// #define FMSPC_SIZE 6
// #define CA_SIZE 10
// #define SGX_CPUSVN_SIZE   16

// const uint32_t TEE_TYPE_SGX = 0x00000000;
// const uint32_t TEE_TYPE_TDX = 0x00000081;
// const uint16_t QUOTE_VERSION_3 = 3;
// const uint16_t QUOTE_VERSION_4 = 4;
//
// const uint16_t ECDSA_256_WITH_P256_CURVE = 2;
// const uint16_t ECDSA_384_WITH_P384_CURVE = 3;
// constexpr size_t ECDSA_P256_SIGNATURE_BYTE_LEN = 64;
// constexpr size_t ENCLAVE_REPORT_BYTE_LEN = 384;
// constexpr size_t TD_REPORT_BYTE_LEN = 584;
//
// const uint16_t PCK_ID_PLAIN_PPID = 1;
// const uint16_t PCK_ID_ENCRYPTED_PPID_2048 = 2;
// const uint16_t PCK_ID_ENCRYPTED_PPID_3072 = 3;
// const uint16_t PCK_ID_PCK_CERTIFICATE = 4;
// const uint16_t PCK_ID_PCK_CERT_CHAIN = 5;
// const uint16_t PCK_ID_QE_REPORT_CERTIFICATION_DATA = 6;
//
// const std::array<uint16_t, 2> ALLOWED_QUOTE_VERSIONS = {{ QUOTE_VERSION_3, QUOTE_VERSION_4 }};
// const std::array<uint32_t, 2> ALLOWED_TEE_TYPES = {{ TEE_TYPE_SGX, TEE_TYPE_TDX }};
// const std::array<uint16_t, 1> ALLOWED_ATTESTATION_KEY_TYPES = {{ ECDSA_256_WITH_P256_CURVE }};
// const std::array<uint8_t, 16> INTEL_QE_VENDOR_ID = {{ 0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9, 0x94, 0x0A, 0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07 }};

const QVE_COLLATERAL_VERSION1: u32 = 0x1;
const QVE_COLLATERAL_VERSION3: u32 = 0x3;
const QVE_COLLATERAL_VERSION31: u32 = 0x00010003;
const QVE_COLLATERAL_VERSION4: u32 = 0x4;

const SGX_ID: &str = "SGX";
const TDX_ID: &str = "TDX";

const QUOTE_MIN_SIZE: usize = 1020;
const QUOTE_CERT_TYPE: u32 = 5;
const CRL_MIN_SIZE: usize = 300;
const PROCESSOR_ISSUER: &str = "Processor";
const PLATFORM_ISSUER: &str =  "Platform";
const PROCESSOR_ISSUER_ID: &str =  "processor";
const PLATFORM_ISSUER_ID: &str =  "platform";
const PEM_CRL_PREFIX: &str =  "-----BEGIN X509 CRL-----";
const PEM_CRL_PREFIX_SIZE: usize = 24;

const INTEL_ROOT_PUB_KEY: [u8; 65] = [
    0x04, 0x0b, 0xa9, 0xc4, 0xc0, 0xc0, 0xc8, 0x61, 0x93, 0xa3, 0xfe, 0x23, 0xd6, 0xb0, 0x2c,
    0xda, 0x10, 0xa8, 0xbb, 0xd4, 0xe8, 0x8e, 0x48, 0xb4, 0x45, 0x85, 0x61, 0xa3, 0x6e, 0x70,
    0x55, 0x25, 0xf5, 0x67, 0x91, 0x8e, 0x2e, 0xdc, 0x88, 0xe4, 0x0d, 0x86, 0x0b, 0xd0, 0xcc,
    0x4e, 0xe2, 0x6a, 0xac, 0xc9, 0x88, 0xe5, 0x05, 0xa9, 0x53, 0x55, 0x8c, 0x45, 0x3f, 0x6b,
    0x09, 0x04, 0xae, 0x73, 0x94
];

/// Perform SGX ECDSA quote verification.
///
/// # Param
/// - **quote\[IN\]**\
/// SGX Quote, presented as u8 vector.
/// - **p_quote_collateral\[IN\]**\
/// This is a pointer to the Quote Certification Collateral provided by the caller.
/// - **expiration_check_date\[IN\]**\
/// This is the date that the QvE will use to determine if any of the inputted collateral have expired.
/// - **p_collateral_expiration_status\[OUT\]**\
/// Address of the outputted expiration status.  This input must not be NULL.
/// - **p_quote_verification_result\[OUT\]**\
/// Address of the outputted quote verification result.
/// - **p_qve_report_info\[IN/OUT\]**\
/// This parameter can be used in 2 ways.\
///     - If p_qve_report_info is NOT None, the API will use Intel QvE to perform quote verification, and QvE will generate a report using the target_info in sgx_ql_qe_report_info_t structure.\
///     - if p_qve_report_info is None, the API will use QVL library to perform quote verification, not that the results can not be cryptographically authenticated in this mode.
/// - **supplemental_data_size\[IN\]**\
/// Size of the buffer pointed to by p_quote (in bytes).
/// - **p_supplemental_data\[OUT\]**\
/// The parameter is optional.  If it is None, supplemental_data_size must be 0.
///
/// # Return
/// Status code of the operation, one of:
/// - *SGX_QL_SUCCESS*
/// - *SGX_QL_ERROR_INVALID_PARAMETER*
/// - *SGX_QL_QUOTE_FORMAT_UNSUPPORTED*
/// - *SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED*
/// - *SGX_QL_UNABLE_TO_GENERATE_REPORT*
/// - *SGX_QL_CRL_UNSUPPORTED_FORMAT*
/// - *SGX_QL_ERROR_UNEXPECTED*
///
pub fn sgx_qv_verify_quote(
    quote: &[u8],
    quote_collateral: QuoteCollateral,
    expiration_check_timestamp: u64,
) {
    // https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteVerification/dcap_quoteverify/sgx_dcap_quoteverify.cpp#L459

    if quote.len() == 0 {
        panic!("qvl::quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER")
    } else if expiration_check_timestamp == 0 {
        panic!("qvl::quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER")
    }

    let tee_type = quote_collateral.tee_type;
    if tee_type != 0 {
        // TODO: 0 SGX 1 TDX 2 UNKNOWN, Only support SGX for now
        panic!("qvl::quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER")
    }

    // TODO: verify supplemental data, ref tee_get_verification_supplemental_data_size

    // TODO: SGX untrusted quote verification path, we may support TDX in the future
    // quote3_error_t sgx_qve_verify_quote(
    //     const uint8_t *p_quote,
    //     uint32_t quote_size,
    //     const struct _sgx_ql_qve_collateral_t *p_quote_collateral,
    //     const time_t expiration_check_date,
    //     uint32_t *p_collateral_expiration_status,
    //     sgx_ql_qv_result_t *p_quote_verification_result,
    //     sgx_ql_qe_report_info_t *p_qve_report_info,
    //     uint32_t supplemental_data_size,
    //     uint8_t *p_supplemental_data)
    // qve_ret = p_tee_qv->tee_verify_evidence(
    //     p_quote, quote_size,
    //     p_quote_collateral,
    //     expiration_check_date,
    //     p_collateral_expiration_status,
    //     p_quote_verification_result,
    //     p_qve_report_info,
    //     supplemental_data_size,
    //     p_supplemental_data);

    // TODO: Check expires
    // TODO: Check quote
    // TODO: Check collateral version
    // TODO: Validate parameters

    // TODO:
    // let version = quote_collateral.major_version;
    // if version != QVE_COLLATERAL_VERSION1 &&
    //     version != QVE_COLLATERAL_VERSION3 &&
    //     version != QVE_COLLATERAL_VERSION31 &&
    //     version != QVE_COLLATERAL_VERSION4 {
    //     return qvl::quote3_error_t::SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED;
    // }

    let quote = Quote::parse(quote).unwrap();
    let certification_data = match quote.signed_data {
        quote::QuoteAuthData::Ecdsa256Bit { certification_data, .. } => {
            Some(certification_data)
        },
        _ => None
    };
    if certification_data.is_none() {
        panic!("qvl::quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER")
    }
    let certification_data = certification_data.unwrap();
    println!("certificate: {}", core::str::from_utf8(&certification_data.data.clone()).unwrap());
    // Concatenated PCK Cert Chain (PEM formatted). PCK Leaf Cert || Intermediate CA Cert || Root CA Cert
    let pems = pem::parse_many(&certification_data.data).unwrap();
    println!("certs: {}", pems.len());
    // TODO: pem.len() == 3
    // let cert = x509_cert::TbsCertificate::from_der(pems.first().unwrap().contents.as_slice());
    let cert_chain: Vec<x509_cert::Certificate> = pems.iter().map(move |pem| x509_cert::Certificate::from_der(&pem.contents).unwrap()).collect();
    println!("{:?}", cert_chain);

    // TODO: Check crl format
    let raw_root_ca_crl = quote_collateral.root_ca_crl;
    // the doc said Version 3 is base16 der, but actually is binary der
    let root_ca_crl = x509_cert::crl::CertificateList::from_der(&raw_root_ca_crl).unwrap();
    println!("{:?}", root_ca_crl);

    let raw_pck_crl = quote_collateral.pck_crl;
    let pck_crl = x509_cert::crl::CertificateList::from_der(&raw_pck_crl).unwrap();
    println!("{:?}", pck_crl);

    let root_cert_pem = pems.last().unwrap(); // TODO: improve this?
    let root_cert = x509_cert::Certificate::from_der(&root_cert_pem.contents).unwrap();
    let root_pub_key_from_cert = root_cert.tbs_certificate.subject_public_key_info.subject_public_key;
    if root_pub_key_from_cert != INTEL_ROOT_PUB_KEY {
        println!("{:?}", root_pub_key_from_cert);
        println!("{:?}", INTEL_ROOT_PUB_KEY);
        panic!("root_pub_key_from_cert != INTEL_ROOT_PUB_KEY");
    }

    let raw_tcb_info_json = quote_collateral.tcb_info;
    let tcb_info = tcb::TCBInfo::from_json_str(&raw_tcb_info_json).unwrap();

    // Get earliest & latest issue date and expiration date comparing all collaterals
    // TODO: this from `qve_get_collateral_dates`
    let raw_qe_identity_issuer_chain = quote_collateral.qe_identity_issuer_chain;
    let raw_qe_identity_issuer_chain = pem::parse_many(raw_qe_identity_issuer_chain).unwrap();
    let qe_identity_issuer_chain: Vec<x509_cert::Certificate> = raw_qe_identity_issuer_chain.iter().map(move |pem| x509_cert::Certificate::from_der(&pem.contents).unwrap()).collect();
    println!("{:?}", qe_identity_issuer_chain);

    let raw_tcb_info_issuer_chain = quote_collateral.tcb_info_issuer_chain;
    let raw_tcb_info_issuer_chain = pem::parse_many(raw_tcb_info_issuer_chain).unwrap();
    let tcb_info_issuer_chain: Vec<x509_cert::Certificate> =
        raw_tcb_info_issuer_chain.iter().map(move |pem| x509_cert::Certificate::from_der(&pem.contents).unwrap()).collect();
    println!("{:?}", tcb_info_issuer_chain);

    let raw_pck_crl_issuer_chain = quote_collateral.pck_crl_issuer_chain;
    let raw_pck_crl_issuer_chain = pem::parse_many(raw_pck_crl_issuer_chain).unwrap();
    let mut pck_crl_issuer_chain: Vec<x509_cert::Certificate> = raw_pck_crl_issuer_chain.iter().map(move |pem| x509_cert::Certificate::from_der(&pem.contents).unwrap()).collect();
    println!("{:?}", pck_crl_issuer_chain);

    let raw_qe_identity_json = quote_collateral.qe_identity;
    let qe_identity = qe_identity::EnclaveIdentity::from_json_str(&raw_qe_identity_json).unwrap();

    // TODO:
    // pckparser::CrlStore root_ca_crl;
    // if (root_ca_crl.parse(crls[0]) != true) {
    //     ret = SGX_QL_CRL_UNSUPPORTED_FORMAT;
    //     break;
    // }
    //
    // pckparser::CrlStore pck_crl;
    // if (pck_crl.parse(crls[1]) != true) {
    //     ret = SGX_QL_CRL_UNSUPPORTED_FORMAT;
    //     break;
    // }
    //
    // CertificateChain pck_crl_issuer_chain;
    // if (pck_crl_issuer_chain.parse((reinterpret_cast<const char*>(p_quote_collateral->pck_crl_issuer_chain))) != STATUS_OK) {
    //     ret = SGX_QL_PCK_CERT_CHAIN_ERROR;
    //     break;
    // }

    // let time = pck_crl_issuer_chain.iter().map(|cert| cert.tbs_certificate.validity.not_before.to_unix_duration()).min().unwrap();
    let earliest_issue_dates = [
        root_ca_crl.tbs_cert_list.this_update.to_unix_duration(), // TODO: earliest_issue[0] = root_ca_crl.getValidity().notBeforeTime
        pck_crl.tbs_cert_list.this_update.to_unix_duration(), // TODO: pck_crl.getValidity().notBeforeTime
        pck_crl_issuer_chain.iter().map(|cert| cert.tbs_certificate.validity.not_before.to_unix_duration()).min().unwrap(),
        cert_chain.iter().map(|cert| cert.tbs_certificate.validity.not_before.to_unix_duration()).min().unwrap(),
        tcb_info_issuer_chain.iter().map(|cert| cert.tbs_certificate.validity.not_before.to_unix_duration()).min().unwrap(),
        qe_identity_issuer_chain.iter().map(|cert| cert.tbs_certificate.validity.not_before.to_unix_duration()).min().unwrap(),
        core::time::Duration::new(tcb_info.issue_date.timestamp() as u64, 0),
        core::time::Duration::new(qe_identity.issue_date.timestamp() as u64, 0)
    ];
    let earliest_issue = earliest_issue_dates.iter().min().unwrap().clone();
    println!("earliest_issue_dates:");
    for date in earliest_issue_dates {
        println!("{:?} {}", date, chrono::Utc.timestamp(date.as_secs() as i64, 0))
    }
    println!("Earliest issue: {}", chrono::Utc.timestamp(earliest_issue.clone().as_secs() as i64, 0));

    let earliest_expiration_dates = [
        root_ca_crl.tbs_cert_list.next_update.unwrap().to_unix_duration(), // TODO: root_ca_crl.getValidity().notAfterTime
        pck_crl.tbs_cert_list.next_update.unwrap().to_unix_duration(), // TODO: pck_crl.getValidity().notBeforeTime
        pck_crl_issuer_chain.iter().map(|cert| cert.tbs_certificate.validity.not_after.to_unix_duration()).min().unwrap(),
        cert_chain.iter().map(|cert| cert.tbs_certificate.validity.not_after.to_unix_duration()).min().unwrap(),
        tcb_info_issuer_chain.iter().map(|cert| cert.tbs_certificate.validity.not_after.to_unix_duration()).min().unwrap(),
        qe_identity_issuer_chain.iter().map(|cert| cert.tbs_certificate.validity.not_after.to_unix_duration()).min().unwrap(),
        core::time::Duration::new(tcb_info.next_update.timestamp() as u64, 0),
        core::time::Duration::new(qe_identity.next_update.timestamp() as u64, 0)
    ];
    let earliest_expiration = earliest_expiration_dates.iter().min().unwrap().clone();
    println!("earliest_expiration_dates:");
    for date in earliest_expiration_dates {
        println!("{:?} {}", date, chrono::Utc.timestamp(date.as_secs() as i64, 0))
    }
    println!("Earliest expiration: {}", chrono::Utc.timestamp(earliest_expiration.clone().as_secs() as i64, 0));

    let latest_issue_dates = [
        root_ca_crl.tbs_cert_list.this_update.to_unix_duration(), // TODO: earliest_issue[0] = root_ca_crl.getValidity().notBeforeTime
        pck_crl.tbs_cert_list.this_update.to_unix_duration(), // TODO: pck_crl.getValidity().notBeforeTime
        pck_crl_issuer_chain.iter().map(|cert| cert.tbs_certificate.validity.not_after.to_unix_duration()).max().unwrap(),
        cert_chain.iter().map(|cert| cert.tbs_certificate.validity.not_after.to_unix_duration()).max().unwrap(),
        tcb_info_issuer_chain.iter().map(|cert| cert.tbs_certificate.validity.not_after.to_unix_duration()).max().unwrap(),
        qe_identity_issuer_chain.iter().map(|cert| cert.tbs_certificate.validity.not_after.to_unix_duration()).max().unwrap(),
        core::time::Duration::new(tcb_info.issue_date.timestamp() as u64, 0),
        core::time::Duration::new(qe_identity.issue_date.timestamp() as u64, 0)
    ];
    let latest_issue = latest_issue_dates.iter().max().unwrap().clone();
    println!("latest_issue_dates:");
    for date in latest_issue_dates {
        println!("{:?} {}", date, chrono::Utc.timestamp(date.as_secs() as i64, 0))
    }
    println!("Latest issue: {}", chrono::Utc.timestamp(latest_issue.clone().as_secs() as i64, 0));

    let latest_expiration_dates = [
        root_ca_crl.tbs_cert_list.next_update.unwrap().to_unix_duration(), // TODO: root_ca_crl.getValidity().notAfterTime
        pck_crl.tbs_cert_list.next_update.unwrap().to_unix_duration(), // TODO: pck_crl.getValidity().notBeforeTime
        pck_crl_issuer_chain.iter().map(|cert| cert.tbs_certificate.validity.not_after.to_unix_duration()).max().unwrap(),
        cert_chain.iter().map(|cert| cert.tbs_certificate.validity.not_after.to_unix_duration()).max().unwrap(),
        tcb_info_issuer_chain.iter().map(|cert| cert.tbs_certificate.validity.not_after.to_unix_duration()).max().unwrap(),
        qe_identity_issuer_chain.iter().map(|cert| cert.tbs_certificate.validity.not_after.to_unix_duration()).max().unwrap(),
        core::time::Duration::new(tcb_info.next_update.timestamp() as u64, 0),
        core::time::Duration::new(qe_identity.next_update.timestamp() as u64, 0)
    ];
    let latest_expiration = latest_expiration_dates.iter().max().unwrap().clone();
    for date in latest_expiration_dates {
        println!("{:?} {}", date, chrono::Utc.timestamp(date.as_secs() as i64, 0))
    }
    println!("Latest expiration: {}", chrono::Utc.timestamp(latest_expiration.clone().as_secs() as i64, 0));

    //parse and verify PCK certificate chain
    // if (earliest_expiration_date <= expiration_check_date) {
    //     *p_collateral_expiration_status = 1;
    // }
    // else {
    //     *p_collateral_expiration_status = 0;
    // }
    // TODO: expiration_check_timestamp can be a duration
    println!("Earliest expiration: {}", chrono::Utc.timestamp(earliest_expiration.clone().as_secs() as i64, 0));
    println!("Expiration: {}", chrono::Utc.timestamp(expiration_check_timestamp as i64, 0));
    if earliest_expiration.as_secs() <= expiration_check_timestamp {
        println!("Expired")
    }

    //TODO: parse and verify TCB info
    // SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/Src/AttestationLibrary/src/QuoteVerification.cpp
    // sgxAttestationVerifyTCBInfo
    // SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/Src/AttestationLibrary/src/Verifiers/TCBInfoVerifier.cpp
    // Status TCBInfoVerifier::verify
    // let cert = webpki::EndEntityCert::try_from(raw_signing_cert).unwrap();


    //TODO: parse and verify QE identity
    // SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/Src/AttestationLibrary/src/QuoteVerification.cpp
    // sgxAttestationVerifyEnclaveIdentity
    // SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/Src/AttestationLibrary/src/Verifiers/EnclaveIdentityVerifier.cpp
    // Status EnclaveIdentityVerifier::verify

    //TODO: parse and verify the quote, update verification results
    // SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/Src/AttestationLibrary/src/QuoteVerification.cpp
    // sgxAttestationVerifyQuote
    // SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp
    // Status QuoteVerifier::verify
}
