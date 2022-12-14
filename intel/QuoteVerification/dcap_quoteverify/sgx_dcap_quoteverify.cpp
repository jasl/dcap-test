/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
 /**
  * File: sgx_dcap_quoteverify.cpp
  *
  * Description: Quote Verification Library
  */

#include "sgx_dcap_quoteverify.h"
#include "sgx_dcap_pcs_com.h"
#include "sgx_dcap_qv_internal.h"
#include "sgx_qve_def.h"
#include "tee_qv_class.h"
#include <stdlib.h>
#include <stdio.h>
#include <new>
#include "se_trace.h"
#include "se_thread.h"
#include "se_memcpy.h"

/**
 * Get supplemental data required size.
 **/
quote3_error_t tee_get_verification_supplemental_data_size(
        uint32_t *p_data_size,
        tee_evidence_type_t tee_type) {

    if (NULL_POINTER(p_data_size)) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    //only support SGX and TDX
    if (tee_type != SGX_EVIDENCE && tee_type != TDX_EVIDENCE)
        return SGX_QL_ERROR_INVALID_PARAMETER;

    uint32_t untrusted_version = 0;
    uint32_t untrusted_size = 0;
    quote3_error_t qve_ret = SGX_QL_ERROR_INVALID_PARAMETER;
    tee_qv_base *p_untrusted_qv = NULL;

    do {
        if (tee_type == SGX_EVIDENCE) {
            p_untrusted_qv = new sgx_qv();
        }
        else if (tee_type == TDX_EVIDENCE) {
            p_untrusted_qv = new tdx_qv();
        }
    } while (0);

    do {
        //call untrusted API to get supplemental data version
        //
        qve_ret = p_untrusted_qv->tee_get_supplemental_data_version(&untrusted_version);
        if (qve_ret != SGX_QL_SUCCESS) {
            SE_TRACE(SE_TRACE_DEBUG, "Error: untrusted API qvl_get_quote_supplemental_data_version failed: 0x%04x\n", qve_ret);
            *p_data_size = 0;
            break;
        }

        //call untrusted API to get supplemental data size
        //
        qve_ret = p_untrusted_qv->tee_get_supplemental_data_size(&untrusted_size);
        if (qve_ret != SGX_QL_SUCCESS) {
            SE_TRACE(SE_TRACE_DEBUG, "Error: untrusted API qvl_get_quote_supplemental_data_size failed: 0x%04x\n", qve_ret);
            *p_data_size = 0;
            break;
        }

        *p_data_size = untrusted_size;
    } while (0) ;

    delete p_untrusted_qv;

    return qve_ret;
}

/**
 * Perform ECDSA quote verification
 **/
quote3_error_t tee_verify_evidence(
        const uint8_t *p_quote,
        uint32_t quote_size,
        const sgx_ql_qve_collateral_t *p_quote_collateral,
        const time_t expiration_check_date,
        uint32_t *p_collateral_expiration_status,
        sgx_ql_qv_result_t *p_quote_verification_result,
        sgx_ql_qe_report_info_t *p_qve_report_info,
        uint32_t supplemental_data_size,
        uint8_t *p_supplemental_data) {

    //validate input parameters
    //
    if (CHECK_MANDATORY_PARAMS(p_quote, quote_size) ||
        NULL_POINTER(p_collateral_expiration_status) ||
        expiration_check_date == 0 ||
        NULL_POINTER(p_quote_verification_result) ||
        CHECK_OPT_PARAMS(p_supplemental_data, supplemental_data_size)) {
        //one or more invalid parameters
        //
        if (p_quote_verification_result) {
            *p_quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
        }
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    //parse quote header to get tee type, only support SGX and TDX by now
    tee_evidence_type_t tee_type = UNKNOWN_QUOTE_TYPE;
    const sgx_quote_header_t *p_header = reinterpret_cast<const sgx_quote_header_t *> (p_quote);
    uint32_t quote_type = p_header->att_key_data_0;
    if (quote_type == 0)
        tee_type = SGX_EVIDENCE;
    else if (quote_type == 0x81)
        tee_type = TDX_EVIDENCE;
    else
        //quote type is not supported
        return SGX_QL_ERROR_INVALID_PARAMETER;

    //validate supplemental data size
    //
    if (p_supplemental_data) {
        quote3_error_t tmp_ret = SGX_QL_ERROR_UNEXPECTED;
        uint32_t tmp_size = 0;
        tmp_ret = tee_get_verification_supplemental_data_size(&tmp_size, tee_type);

        if (tmp_ret != SGX_QL_SUCCESS || tmp_size > supplemental_data_size) {

            if (p_quote_verification_result) {
                *p_quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
            }
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
    }

    quote3_error_t qve_ret = SGX_QL_ERROR_UNEXPECTED;
    unsigned char fmspc_from_quote[FMSPC_SIZE] = { 0 };
    unsigned char ca_from_quote[CA_SIZE] = { 0 };
    struct _sgx_ql_qve_collateral_t* qve_collaterals_from_qp = NULL;
    tee_qv_base *p_tee_qv = NULL;

    do {
        //untrsuted quote verification
        //
        try {
            if (tee_type == SGX_EVIDENCE)
                p_tee_qv = new sgx_qv();
            if (tee_type == TDX_EVIDENCE)
                p_tee_qv = new tdx_qv();
        }

        catch (std::bad_alloc&) {
            qve_ret = SGX_QL_ERROR_OUT_OF_MEMORY;
            break;
        }

        //in case input collateral is NULL, dynamically load and call QPL to retrieve verification collateral
        //
        if (NULL_POINTER(p_quote_collateral)) {

            //extract fmspc and CA from the quote, these values are required inorder to query collateral from QPL
            //
            qve_ret = p_tee_qv->tee_get_fmspc_ca_from_quote(p_quote, quote_size, fmspc_from_quote, FMSPC_SIZE, ca_from_quote, CA_SIZE);
            if (qve_ret == SGX_QL_SUCCESS) {
                SE_TRACE(SE_TRACE_DEBUG, "Info: get_fmspc_ca_from_quote successfully returned.\n");
            }
            else {
                SE_TRACE(SE_TRACE_DEBUG, "Error: get_fmspc_ca_from_quote failed: 0x%04x\n", qve_ret);
                break;
            }

            //retrieve verification collateral using QPL
            //
            qve_ret = p_tee_qv->tee_get_verification_endorsement(
                    (const char *)fmspc_from_quote,
                    FMSPC_SIZE,
                    (const char *)ca_from_quote,
                    &qve_collaterals_from_qp);
            if (qve_ret == SGX_QL_SUCCESS) {
                SE_TRACE(SE_TRACE_DEBUG, "Info: dcap_retrieve_verification_collateral successfully returned.\n");
            }
            else {
                SE_TRACE(SE_TRACE_DEBUG, "Error: dcap_retrieve_verification_collateral failed: 0x%04x\n", qve_ret);
                break;
            }
            p_quote_collateral = qve_collaterals_from_qp;
        }

        qve_ret = p_tee_qv->tee_verify_evidence(
                p_quote, quote_size,
                p_quote_collateral,
                expiration_check_date,
                p_collateral_expiration_status,
                p_quote_verification_result,
                p_qve_report_info,
                supplemental_data_size,
                p_supplemental_data);
        if (qve_ret == SGX_QL_SUCCESS) {
            SE_TRACE(SE_TRACE_DEBUG, "Info: verify_quote successfully returned.\n");
        }
        else {
            SE_TRACE(SE_TRACE_DEBUG, "Error: verify_quote failed: 0x%04x\n", qve_ret);
            break;
        }
    } while (0);

    //free verification collateral using QPL
    //
    if (qve_collaterals_from_qp) {
        p_tee_qv->tee_free_verification_endorsement(qve_collaterals_from_qp);
    }

    return qve_ret;
}

/**
 * Get SGX supplemental data required size.
 **/
quote3_error_t sgx_qv_get_quote_supplemental_data_size(uint32_t *p_data_size)
{
    return tee_get_verification_supplemental_data_size(p_data_size, SGX_EVIDENCE);
}

/**
 * Perform SGX ECDSA quote verification
 **/
quote3_error_t sgx_qv_verify_quote(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    uint32_t supplemental_data_size,
    uint8_t *p_supplemental_data)
{
    return tee_verify_evidence(
        p_quote,
        quote_size,
        p_quote_collateral,
        expiration_check_date,
        p_collateral_expiration_status,
        p_quote_verification_result,
        p_qve_report_info,
        supplemental_data_size,
        p_supplemental_data);
}

/**
 * Get TDX supplemental data required size.
 **/
quote3_error_t tdx_qv_get_quote_supplemental_data_size(uint32_t *p_data_size)
{
    return tee_get_verification_supplemental_data_size(p_data_size, TDX_EVIDENCE);
}

/**
 * Perform TDX ECDSA quote verification
 **/
quote3_error_t tdx_qv_verify_quote(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const tdx_ql_qve_collateral_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    uint32_t supplemental_data_size,
    uint8_t *p_supplemental_data)
{
    return tee_verify_evidence(
        p_quote,
        quote_size,
        p_quote_collateral,
        expiration_check_date,
        p_collateral_expiration_status,
        p_quote_verification_result,
        p_qve_report_info,
        supplemental_data_size,
        p_supplemental_data);
}
