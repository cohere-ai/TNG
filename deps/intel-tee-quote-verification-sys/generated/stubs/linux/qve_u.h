/*
 * Stands in for the qve_u.h Intel's Makefile generates from ae/QvE/qve/qve.edl with the SGX
 * SDK's sgx_edger8r: the calls into the Quote Verification Enclave (QvE). The library only
 * enters the QvE when a caller asks for an enclave-signed result (a non-NULL
 * p_qve_report_info) on SGX hardware; Trustee never does, and the client machines this build
 * is for have no SGX. Each call fails as the generated bridge does when the enclave cannot be
 * entered: it returns an SGX error and leaves *retval alone, so callers report the error
 * value they initialised it with.
 *
 * The declarations are those of the generated header for DCAP_1.27, so they carry Intel's
 * notice: Copyright (C) 2011-2021 Intel Corporation. All rights reserved. BSD-3-Clause, see
 * the DCAP repository's License.txt (licenses/ in this crate).
 */
#ifndef QVE_U_H__
#define QVE_U_H__

#include <stdint.h>
#include <time.h>
#include "sgx_edger8r.h"
#include "sgx_qve_header.h"
#include "sgx_qve_def.h"

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t get_fmspc_ca_from_quote(sgx_enclave_id_t eid, quote3_error_t* retval, const uint8_t* quote, uint32_t quote_size, unsigned char* fmsp_from_quote, uint32_t fmsp_from_quote_size, unsigned char* ca_from_quote, uint32_t ca_from_quote_size);
sgx_status_t sgx_qve_get_quote_supplemental_data_size(sgx_enclave_id_t eid, quote3_error_t* retval, uint32_t* p_data_size);
sgx_status_t sgx_qve_get_quote_supplemental_data_version(sgx_enclave_id_t eid, quote3_error_t* retval, uint32_t* p_version);
sgx_status_t sgx_qve_verify_quote(sgx_enclave_id_t eid, quote3_error_t* retval, const uint8_t* p_quote, uint32_t quote_size, const struct _sgx_ql_qve_collateral_t* p_quote_collateral, time_t expiration_check_date, uint32_t* p_collateral_expiration_status, sgx_ql_qv_result_t* p_quote_verification_result, sgx_ql_qe_report_info_t* p_qve_report_info, uint32_t supplemental_data_size, uint8_t* p_supplemental_data);
sgx_status_t tee_qve_verify_quote_qvt(sgx_enclave_id_t eid, quote3_error_t* retval, const uint8_t* p_quote, uint32_t quote_size, time_t current_time, const struct _sgx_ql_qve_collateral_t* p_quote_collateral, sgx_ql_qe_report_info_t* p_qve_report_info, const uint8_t* p_user_data, uint32_t user_data_size, uint32_t* p_verification_result_token_buffer_size, uint8_t** p_verification_result_token);

#ifdef __cplusplus
}
#endif

#endif
