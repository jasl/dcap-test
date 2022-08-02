use anyhow::Result;
use std::fs;

// DCAP Verification relates
use std::time::SystemTime;
use core::mem::size_of;
use sgx_dcap_quoteverify_rs as qvl;

fn create_quote_vec(data: &[u8]) -> Result<Vec<u8>> {
    // TODO: DCAP-only for now, should determine which RA type via `/dev/attestation/attestation_type`
    fs::write("/dev/attestation/user_report_data", data)?;
    Ok(fs::read("/dev/attestation/quote")?)
}

/// Quote verification with QvE/QVL
///
/// # Param
/// - **quote**\
/// ECDSA quote buffer.
/// - **use_qve**\
/// Set quote verification mode.\
///     - If true, quote verification will be performed by Intel QvE.
///     - If false, quote verification will be performed by untrusted QVL.
///
fn ecdsa_quote_verification(quote: &[u8]) {
    let mut quote_verification_result = qvl::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;
    let mut collateral_expiration_status = 1u32;

    println!("1");

    // set current time. This is only for sample purposes, in production mode a trusted time should be used.
    //
    let current_time: i64 = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs().try_into().unwrap();

    println!("2");

    // call DCAP quote verify library for quote verification
    // here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
    // if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
    // if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
    let dcap_ret = qvl::sgx_qv_verify_quote(
        quote,
        None,
        current_time,
        &mut collateral_expiration_status,
        &mut quote_verification_result,
        None,
        0,
        None);
    if qvl::quote3_error_t::SGX_QL_SUCCESS == dcap_ret {
        println!("\tInfo: App: sgx_qv_verify_quote successfully returned.");
    } else {
        println!("\tError: App: sgx_qv_verify_quote failed: {:#04x}", dcap_ret as u32);
    }

    println!("3");

    // check verification result
    //
    match quote_verification_result {
        qvl::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => {
            // check verification collateral expiration status
            // this value should be considered in your own attestation/verification policy
            //
            if 0u32 == collateral_expiration_status {
                println!("\tInfo: App: Verification completed successfully.");
            } else {
                println!("\tWarning: App: Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.");
            }
        },
        qvl::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED |
        qvl::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE |
        qvl::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED |
        qvl::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED |
        qvl::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
            println!("\tWarning: App: Verification completed with Non-terminal result: {:x}", quote_verification_result as u32);
        },
        qvl::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_INVALID_SIGNATURE |
        qvl::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_REVOKED |
        qvl::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED | _ => {
            println!("\tError: App: Verification completed with Terminal result: {:x}", quote_verification_result as u32);
        },
    }

    println!("4");
}

fn main() {
    let quote = create_quote_vec("Hello, world!".as_bytes()).expect("Create quote error");
    println!("0x{}", hex::encode(quote.clone()));

    ecdsa_quote_verification(quote.clone().as_slice());
}
