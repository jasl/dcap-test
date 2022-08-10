{
global:
    sgx_qv_verify_quote;
    sgx_qv_get_quote_supplemental_data_size;
    sgx_qv_set_enclave_load_policy;
    sgx_qv_get_qve_identity;
    sgx_qv_free_qve_identity;
    sgx_qv_set_path;
    tdx_qv_get_quote_supplemental_data_size;
    tdx_qv_verify_quote;

    sgx_qvl_verify_quote;
    sgx_qvl_get_quote_supplemental_data_size;
    sgx_qvl_get_quote_supplemental_data_version;
    qvl_get_fmspc_ca_from_quote;

    sgx_dcap_retrieve_verification_collateral;
    sgx_dcap_free_verification_collateral;
    sgx_dcap_retrieve_qve_identity;
    sgx_dcap_free_qve_identity;
    tdx_dcap_retrieve_verification_collateral;
    tdx_dcap_free_verification_collateral;
local:
    *;
};
