/* See linux/qve_u.h. */
#include "linux/qve_u.h"

sgx_status_t get_fmspc_ca_from_quote(sgx_enclave_id_t eid, quote3_error_t* retval, const uint8_t* quote, uint32_t quote_size, unsigned char* fmsp_from_quote, uint32_t fmsp_from_quote_size, unsigned char* ca_from_quote, uint32_t ca_from_quote_size)
{
    (void)eid; (void)retval; (void)quote; (void)quote_size; (void)fmsp_from_quote; (void)fmsp_from_quote_size; (void)ca_from_quote; (void)ca_from_quote_size;
    return SGX_ERROR_NO_DEVICE;
}

sgx_status_t sgx_qve_get_quote_supplemental_data_size(sgx_enclave_id_t eid, quote3_error_t* retval, uint32_t* p_data_size)
{
    (void)eid; (void)retval; (void)p_data_size;
    return SGX_ERROR_NO_DEVICE;
}

sgx_status_t sgx_qve_get_quote_supplemental_data_version(sgx_enclave_id_t eid, quote3_error_t* retval, uint32_t* p_version)
{
    (void)eid; (void)retval; (void)p_version;
    return SGX_ERROR_NO_DEVICE;
}

sgx_status_t sgx_qve_verify_quote(sgx_enclave_id_t eid, quote3_error_t* retval, const uint8_t* p_quote, uint32_t quote_size, const struct _sgx_ql_qve_collateral_t* p_quote_collateral, time_t expiration_check_date, uint32_t* p_collateral_expiration_status, sgx_ql_qv_result_t* p_quote_verification_result, sgx_ql_qe_report_info_t* p_qve_report_info, uint32_t supplemental_data_size, uint8_t* p_supplemental_data)
{
    (void)eid; (void)retval; (void)p_quote; (void)quote_size; (void)p_quote_collateral; (void)expiration_check_date; (void)p_collateral_expiration_status; (void)p_quote_verification_result; (void)p_qve_report_info; (void)supplemental_data_size; (void)p_supplemental_data;
    return SGX_ERROR_NO_DEVICE;
}

sgx_status_t tee_qve_verify_quote_qvt(sgx_enclave_id_t eid, quote3_error_t* retval, const uint8_t* p_quote, uint32_t quote_size, time_t current_time, const struct _sgx_ql_qve_collateral_t* p_quote_collateral, sgx_ql_qe_report_info_t* p_qve_report_info, const uint8_t* p_user_data, uint32_t user_data_size, uint32_t* p_verification_result_token_buffer_size, uint8_t** p_verification_result_token)
{
    (void)eid; (void)retval; (void)p_quote; (void)quote_size; (void)current_time; (void)p_quote_collateral; (void)p_qve_report_info; (void)p_user_data; (void)user_data_size; (void)p_verification_result_token_buffer_size; (void)p_verification_result_token;
    return SGX_ERROR_NO_DEVICE;
}
