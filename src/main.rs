#![feature(new_uninit)]
#![feature(strict_provenance)]

extern crate core;

use anyhow::Result;
use std::{fs, ptr, time};
use sgx_dcap_quoteverify_rs as qvl;

// #define FMSPC_SIZE 6
// #define CA_SIZE 10
const FMSPC_SIZE: usize = 6;
const CA_SIZE: usize = 10;

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
    let mut supplemental_data_size = 0u32;      // mem::zeroed() is safe as long as the struct doesn't have zero-invalid types, like pointers
    let mut supplemental_data: qvl::sgx_ql_qv_supplemental_t = unsafe { std::mem::zeroed() };
    let mut quote_verification_result = qvl::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;
    let mut collateral_expiration_status = 1u32;

    let mut fmsp_from_quote: [u8; FMSPC_SIZE] = [0u8; FMSPC_SIZE];
    let mut ca_from_quote: [u8; CA_SIZE] = [0u8; CA_SIZE];
    let dcap_ret = qvl::qvl_get_fmspc_ca_from_quote(
        quote,
        &mut fmsp_from_quote,
        &mut ca_from_quote
    );

    if qvl::quote3_error_t::SGX_QL_SUCCESS == dcap_ret {
        println!("Info: qvl_get_fmspc_ca_from_quote successfully returned.");
    } else {
        panic!("Error: qvl_get_fmspc_ca_from_quote failed: {:#04x}", dcap_ret as u32);
    }

    let mut p_quote_collateral: *mut qvl::sgx_ql_qve_collateral_t = ptr::null_mut();
    let dcap_ret = qvl::sgx_dcap_retrieve_verification_collateral(
        &fmsp_from_quote,
        &ca_from_quote,
        &mut p_quote_collateral as *mut *mut qvl::sgx_ql_qve_collateral_t
    );

    if qvl::quote3_error_t::SGX_QL_SUCCESS == dcap_ret {
        println!("Info: sgx_dcap_retrieve_verification_collateral successfully returned.");
    } else {
        panic!("Error: sgx_dcap_retrieve_verification_collateral failed: {:#04x}", dcap_ret as u32);
    }

    let quote_collateral: &qvl::sgx_ql_qve_collateral_t = &unsafe { *p_quote_collateral };

    // Untrusted quote verification

    // call DCAP quote verify library to get supplemental data size
    //
    let dcap_ret = qvl::sgx_qv_get_quote_supplemental_data_size(&mut supplemental_data_size);
    if qvl::quote3_error_t::SGX_QL_SUCCESS == dcap_ret && std::mem::size_of::<qvl::sgx_ql_qv_supplemental_t>() as u32 == supplemental_data_size {
        println!("\tInfo: sgx_qv_get_quote_supplemental_data_size successfully returned.");
    } else {
        if dcap_ret != qvl::quote3_error_t::SGX_QL_SUCCESS {
            println!("\tError: sgx_qv_get_quote_supplemental_data_size failed: {:#04x}", dcap_ret as u32);
        }
        if supplemental_data_size != std::mem::size_of::<qvl::sgx_ql_qv_supplemental_t>().try_into().unwrap() {
            println!("\tWarning: Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.");
        }
        supplemental_data_size = 0u32;
    }

    // set current time. This is only for sample purposes, in production mode a trusted time should be used.
    //
    let current_time: i64 = time::SystemTime::now().duration_since(time::SystemTime::UNIX_EPOCH).unwrap().as_secs().try_into().unwrap();

    let p_supplemental_data = match supplemental_data_size {
        0 => None,
        _ => Some(&mut supplemental_data),
    };

    println!("FMSP hex:");
    println!("0x{}", hex::encode(fmsp_from_quote.clone()));
    println!("CA hex:");
    println!("0x{}", hex::encode(ca_from_quote.clone()));

    // typedef struct _sgx_ql_qve_collateral_t {
    // 	uint32_t version;
    // 	uint32_t tee_type;
    // 	char* pck_crl_issuer_chain;
    // 	uint32_t pck_crl_issuer_chain_size;
    // 	char* root_ca_crl;
    // 	uint32_t root_ca_crl_size;
    // 	char* pck_crl;
    // 	uint32_t pck_crl_size;
    // 	char* tcb_info_issuer_chain;
    // 	uint32_t tcb_info_issuer_chain_size;
    // 	char* tcb_info;
    // 	uint32_t tcb_info_size;
    // 	char* qe_identity_issuer_chain;
    // 	uint32_t qe_identity_issuer_chain_size;
    // 	char* qe_identity;
    // 	uint32_t qe_identity_size;
    // } _sgx_ql_qve_collateral_t;

    println!("Collateral TEE type:");
    println!("{}", quote_collateral.tee_type);
    println!("Collateral PCK CRL issuer chain size:");
    println!("{}", quote_collateral.pck_crl_issuer_chain_size);
    println!("Collateral ROOT CA CRL size:");
    println!("{}", quote_collateral.root_ca_crl_size);
    println!("Collateral TCB info size:");
    println!("{}", quote_collateral.tcb_info_size);
    println!("Collateral QE identity issuer chain size:");
    println!("{}", quote_collateral.qe_identity_issuer_chain_size);
    println!("Collateral QE Identity ize:");
    println!("{}", quote_collateral.qe_identity_size);

    // call DCAP quote verify library for quote verification
    // here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
    // if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
    // if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
    let dcap_ret = qvl::sgx_qv_verify_quote(
        quote,
        Some(quote_collateral),
        current_time,
        &mut collateral_expiration_status,
        &mut quote_verification_result,
        None,
        supplemental_data_size,
        p_supplemental_data);
    if qvl::quote3_error_t::SGX_QL_SUCCESS == dcap_ret {
        println!("\tInfo: App: sgx_qv_verify_quote successfully returned.");
    } else {
        println!("\tError: App: sgx_qv_verify_quote failed: {:#04x}", dcap_ret as u32);
    }

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

    // check supplemental data if necessary
    //
    if supplemental_data_size > 0 {

        // you can check supplemental data based on your own attestation/verification policy
        // here we only print supplemental data version for demo usage
        //
        println!("\tInfo: Supplemental data version: {}", supplemental_data.version);
    }
}

fn main() {
    let quote = create_quote_vec("Hello, world!".as_bytes()).expect("Create quote error");
    // fs::write("/data/storage_files/quote.dat", quote.clone()).expect("Write error");

    println!("Quote hex:");
    println!("0x{}", hex::encode(quote.clone()));

    println!("Untrusted quote verification:");
    ecdsa_quote_verification(&quote);

    println!("Done");
}
