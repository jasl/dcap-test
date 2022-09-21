use serde_json::Value::String;
use sgx_dcap_quoteverify_rs as qvl;
use crate::{Quote, quote};

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
    quote_collateral: &qvl::sgx_ql_qve_collateral_t,
    expiration_check_timestamp: u64,
) -> qvl::quote3_error_t {
    // https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteVerification/dcap_quoteverify/sgx_dcap_quoteverify.cpp#L459

    if quote.len() == 0 {
        return qvl::quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER
    } else if expiration_check_timestamp == 0 {
        return qvl::quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER
    }

    let tee_type = quote_collateral.tee_type;
    if tee_type != 0 {
        // TODO: 0 SGX 1 TDX 2 UNKNOWN, Only support SGX for now
        return qvl::quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER
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

    let version = unsafe { quote_collateral.__bindgen_anon_1.version };
    if version != QVE_COLLATERAL_VERSION1 &&
        version != QVE_COLLATERAL_VERSION3 &&
        version != QVE_COLLATERAL_VERSION31 &&
        version != QVE_COLLATERAL_VERSION4 {
        return qvl::quote3_error_t::SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED;
    }

    let quote = Quote::parse(quote).unwrap();
    let certification_data = match quote.signed_data {
        quote::QuoteAuthData::Ecdsa256Bit { certification_data, .. } => {
            Some(certification_data)
        },
        _ => None
    };
    if certification_data.is_none() {
        return qvl::quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER
    }
    let certification_data = certification_data.unwrap();
    println!("certificate: {}", core::str::from_utf8(&certification_data.data.clone()).unwrap_or(format!("0x{}", hex::encode(certification_data.data.clone())).as_str()));

    // TODO: ret = extract_chain_from_quote(p_quote, quote_size, &pck_cert_chain_size, &p_pck_cert_chain);

    qvl::quote3_error_t::SGX_QL_SUCCESS
}
