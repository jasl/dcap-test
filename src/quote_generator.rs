use sgx_dcap_quoteverify_rs as qvl;
use std::{fs, ptr, time};

const FMSPC_SIZE: usize = 6;
const CA_SIZE: usize = 10;

pub struct QuoteBag {
    // TODO: Version of the bag
    pub quote: Vec<u8>,
    pub quote_collateral: qvl::sgx_ql_qve_collateral_t,
}

pub fn create_quote_bag(data: &[u8]) -> QuoteBag {
    // TODO: DCAP-only for now, should determine which RA type via `/dev/attestation/attestation_type`
    fs::write("/dev/attestation/user_report_data", data).expect("Write user report data error");
    let quote = fs::read("/dev/attestation/quote").expect("Create quote error");

    println!("Quote hex:");
    println!("0x{}", hex::encode(quote.clone()));

    let mut fmsp_from_quote: [u8; FMSPC_SIZE] = [0u8; FMSPC_SIZE];
    let mut ca_from_quote: [u8; CA_SIZE] = [0u8; CA_SIZE];

    let dcap_ret = qvl::qvl_get_fmspc_ca_from_quote(
        &quote,
        &mut fmsp_from_quote,
        &mut ca_from_quote
    );

    if qvl::quote3_error_t::SGX_QL_SUCCESS == dcap_ret {
        println!("Info: qvl_get_fmspc_ca_from_quote successfully returned.");
    } else {
        panic!("Error: qvl_get_fmspc_ca_from_quote failed: {:#04x}", dcap_ret as u32);
    }

    println!("FMSP hex:");
    println!("0x{}", hex::encode(fmsp_from_quote.clone()));
    println!("CA hex:");
    println!("0x{}", hex::encode(ca_from_quote.clone()));

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

    // TODO: may requires to free collateral

    QuoteBag {
        quote,
        quote_collateral: *quote_collateral
    }
}

pub fn quote_verification(quote: Vec<u8>, quote_collateral: qvl::sgx_ql_qve_collateral_t) {
    // set current time. This is only for sample purposes, in production mode a trusted time should be used.
    //
    let current_time: u64 = time::SystemTime::now().duration_since(time::SystemTime::UNIX_EPOCH).unwrap().as_secs().try_into().unwrap();

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
    println!("Collateral Version:");
    println!("{}", unsafe { quote_collateral.__bindgen_anon_1.version });
    // TODO: Bindgen generate __bindgen_anon_1: _sgx_ql_qve_collateral_t__bindgen_ty_1 not version
    // println!("{}", quote_collateral.version);
    println!("Collateral PCK CRL issuer chain size:");
    println!("{}", quote_collateral.pck_crl_issuer_chain_size);
    println!("Collateral PCK CRL issuer chain data:");
    let pck_crl_issuer_chain = unsafe {
        let slice = core::slice::from_raw_parts(
            quote_collateral.pck_crl_issuer_chain as *const u8,
            quote_collateral.pck_crl_issuer_chain_size as usize,
        );

        core::str::from_utf8(slice).expect("Collateral PCK CRL issuer chain should an UTF-8 string")
    };
    println!("{}", pck_crl_issuer_chain);
    println!("Collateral ROOT CA CRL size:");
    println!("{}", quote_collateral.root_ca_crl_size);
    println!("Collateral ROOT CA CRL data:");
    let root_ca_crl = unsafe {
        let slice = core::slice::from_raw_parts(
            quote_collateral.root_ca_crl as *const u8,
            quote_collateral.root_ca_crl_size as usize
        );

        slice.to_vec()
    };
    println!("0x{}", hex::encode(root_ca_crl.clone()));
    println!("Collateral TCB info size:");
    println!("{}", quote_collateral.tcb_info_size);
    println!("Collateral TCB info data:");
    let tcb_info = unsafe {
        let slice = core::slice::from_raw_parts(
            quote_collateral.tcb_info as *const u8,
            quote_collateral.tcb_info_size as usize
        );

        core::str::from_utf8(slice).expect("Collateral TCB info should an UTF-8 string")
    };
    println!("{}", tcb_info);
    println!("Collateral QE identity issuer chain size:");
    println!("{}", quote_collateral.qe_identity_issuer_chain_size);
    println!("Collateral QE identity issuer chain data:");
    let qe_identity_issuer_chain = unsafe {
        let slice = core::slice::from_raw_parts(
            quote_collateral.qe_identity_issuer_chain as *const u8,
            quote_collateral.qe_identity_issuer_chain_size as usize
        );

        core::str::from_utf8(slice).expect("Collateral QE identity issuer chain should an UTF-8 string")
    };
    println!("{}", qe_identity_issuer_chain);
    println!("Collateral QE Identity size:");
    println!("{}", quote_collateral.qe_identity_size);
    println!("Collateral QE identity data:");
    let qe_identity = unsafe {
        let slice = core::slice::from_raw_parts(
            quote_collateral.qe_identity as *const u8,
            quote_collateral.qe_identity_size as usize
        );

        core::str::from_utf8(slice).expect("Collateral QE Identity should an UTF-8 string")
    };
    println!("{}", qe_identity);

    // call DCAP quote verify library for quote verification
    // here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
    // if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
    // if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
    let mut quote_verification_result = qvl::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;
    let mut collateral_expiration_status = 1u32;

    let dcap_ret = qvl::sgx_qv_verify_quote(
        &quote,
        Some(&quote_collateral),
        current_time as i64, // TODO: WHY i64?
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

    // check verification result

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
}
