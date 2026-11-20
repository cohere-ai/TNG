#include "qve_u.h"
#include <errno.h>

typedef struct ms_get_fmspc_ca_from_quote_t {
	quote3_error_t ms_retval;
	const uint8_t* ms_quote;
	uint32_t ms_quote_size;
	unsigned char* ms_fmsp_from_quote;
	uint32_t ms_fmsp_from_quote_size;
	unsigned char* ms_ca_from_quote;
	uint32_t ms_ca_from_quote_size;
} ms_get_fmspc_ca_from_quote_t;

typedef struct ms_sgx_qve_get_quote_supplemental_data_size_t {
	quote3_error_t ms_retval;
	uint32_t* ms_p_data_size;
} ms_sgx_qve_get_quote_supplemental_data_size_t;

typedef struct ms_sgx_qve_get_quote_supplemental_data_version_t {
	quote3_error_t ms_retval;
	uint32_t* ms_p_version;
} ms_sgx_qve_get_quote_supplemental_data_version_t;

typedef struct ms_sgx_qve_verify_quote_t {
	quote3_error_t ms_retval;
	const uint8_t* ms_p_quote;
	uint32_t ms_quote_size;
	const struct _sgx_ql_qve_collateral_t* ms_p_quote_collateral;
	time_t ms_expiration_check_date;
	uint32_t* ms_p_collateral_expiration_status;
	sgx_ql_qv_result_t* ms_p_quote_verification_result;
	sgx_ql_qe_report_info_t* ms_p_qve_report_info;
	uint32_t ms_supplemental_data_size;
	uint8_t* ms_p_supplemental_data;
} ms_sgx_qve_verify_quote_t;

typedef struct ms_tee_qve_verify_quote_qvt_t {
	quote3_error_t ms_retval;
	const uint8_t* ms_p_quote;
	uint32_t ms_quote_size;
	time_t ms_current_time;
	const struct _sgx_ql_qve_collateral_t* ms_p_quote_collateral;
	sgx_ql_qe_report_info_t* ms_p_qve_report_info;
	const uint8_t* ms_p_user_data;
	uint32_t ms_user_data_size;
	uint32_t* ms_p_verification_result_token_buffer_size;
	uint8_t** ms_p_verification_result_token;
} ms_tee_qve_verify_quote_qvt_t;

typedef struct ms_ocall_qvt_token_malloc_t {
	uint64_t ms_verification_result_token_buffer_size;
	uint8_t** ms_p_verification_result_token;
} ms_ocall_qvt_token_malloc_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_u_sgxssl_ftime_t {
	void* ms_timeptr;
	uint32_t ms_timeb_len;
} ms_u_sgxssl_ftime_t;

typedef struct ms_pthread_wait_timeout_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
	unsigned long long ms_timeout;
} ms_pthread_wait_timeout_ocall_t;

typedef struct ms_pthread_create_ocall_t {
	int ms_retval;
	unsigned long long ms_self;
} ms_pthread_create_ocall_t;

typedef struct ms_pthread_wakeup_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
} ms_pthread_wakeup_ocall_t;

static sgx_status_t SGX_CDECL qve_ocall_qvt_token_malloc(void* pms)
{
	ms_ocall_qvt_token_malloc_t* ms = SGX_CAST(ms_ocall_qvt_token_malloc_t*, pms);
	ocall_qvt_token_malloc(ms->ms_verification_result_token_buffer_size, ms->ms_p_verification_result_token);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL qve_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL qve_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL qve_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL qve_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL qve_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL qve_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL qve_pthread_wait_timeout_ocall(void* pms)
{
	ms_pthread_wait_timeout_ocall_t* ms = SGX_CAST(ms_pthread_wait_timeout_ocall_t*, pms);
	ms->ms_retval = pthread_wait_timeout_ocall(ms->ms_waiter, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL qve_pthread_create_ocall(void* pms)
{
	ms_pthread_create_ocall_t* ms = SGX_CAST(ms_pthread_create_ocall_t*, pms);
	ms->ms_retval = pthread_create_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL qve_pthread_wakeup_ocall(void* pms)
{
	ms_pthread_wakeup_ocall_t* ms = SGX_CAST(ms_pthread_wakeup_ocall_t*, pms);
	ms->ms_retval = pthread_wakeup_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[10];
} ocall_table_qve = {
	10,
	{
		(void*)qve_ocall_qvt_token_malloc,
		(void*)qve_sgx_oc_cpuidex,
		(void*)qve_sgx_thread_wait_untrusted_event_ocall,
		(void*)qve_sgx_thread_set_untrusted_event_ocall,
		(void*)qve_sgx_thread_setwait_untrusted_events_ocall,
		(void*)qve_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)qve_u_sgxssl_ftime,
		(void*)qve_pthread_wait_timeout_ocall,
		(void*)qve_pthread_create_ocall,
		(void*)qve_pthread_wakeup_ocall,
	}
};
sgx_status_t get_fmspc_ca_from_quote(sgx_enclave_id_t eid, quote3_error_t* retval, const uint8_t* quote, uint32_t quote_size, unsigned char* fmsp_from_quote, uint32_t fmsp_from_quote_size, unsigned char* ca_from_quote, uint32_t ca_from_quote_size)
{
	sgx_status_t status;
	ms_get_fmspc_ca_from_quote_t ms;
	ms.ms_quote = quote;
	ms.ms_quote_size = quote_size;
	ms.ms_fmsp_from_quote = fmsp_from_quote;
	ms.ms_fmsp_from_quote_size = fmsp_from_quote_size;
	ms.ms_ca_from_quote = ca_from_quote;
	ms.ms_ca_from_quote_size = ca_from_quote_size;
	status = sgx_ecall(eid, 0, &ocall_table_qve, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_qve_get_quote_supplemental_data_size(sgx_enclave_id_t eid, quote3_error_t* retval, uint32_t* p_data_size)
{
	sgx_status_t status;
	ms_sgx_qve_get_quote_supplemental_data_size_t ms;
	ms.ms_p_data_size = p_data_size;
	status = sgx_ecall(eid, 1, &ocall_table_qve, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_qve_get_quote_supplemental_data_version(sgx_enclave_id_t eid, quote3_error_t* retval, uint32_t* p_version)
{
	sgx_status_t status;
	ms_sgx_qve_get_quote_supplemental_data_version_t ms;
	ms.ms_p_version = p_version;
	status = sgx_ecall(eid, 2, &ocall_table_qve, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_qve_verify_quote(sgx_enclave_id_t eid, quote3_error_t* retval, const uint8_t* p_quote, uint32_t quote_size, const struct _sgx_ql_qve_collateral_t* p_quote_collateral, time_t expiration_check_date, uint32_t* p_collateral_expiration_status, sgx_ql_qv_result_t* p_quote_verification_result, sgx_ql_qe_report_info_t* p_qve_report_info, uint32_t supplemental_data_size, uint8_t* p_supplemental_data)
{
	sgx_status_t status;
	ms_sgx_qve_verify_quote_t ms;
	ms.ms_p_quote = p_quote;
	ms.ms_quote_size = quote_size;
	ms.ms_p_quote_collateral = p_quote_collateral;
	ms.ms_expiration_check_date = expiration_check_date;
	ms.ms_p_collateral_expiration_status = p_collateral_expiration_status;
	ms.ms_p_quote_verification_result = p_quote_verification_result;
	ms.ms_p_qve_report_info = p_qve_report_info;
	ms.ms_supplemental_data_size = supplemental_data_size;
	ms.ms_p_supplemental_data = p_supplemental_data;
	status = sgx_ecall(eid, 3, &ocall_table_qve, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t tee_qve_verify_quote_qvt(sgx_enclave_id_t eid, quote3_error_t* retval, const uint8_t* p_quote, uint32_t quote_size, time_t current_time, const struct _sgx_ql_qve_collateral_t* p_quote_collateral, sgx_ql_qe_report_info_t* p_qve_report_info, const uint8_t* p_user_data, uint32_t user_data_size, uint32_t* p_verification_result_token_buffer_size, uint8_t** p_verification_result_token)
{
	sgx_status_t status;
	ms_tee_qve_verify_quote_qvt_t ms;
	ms.ms_p_quote = p_quote;
	ms.ms_quote_size = quote_size;
	ms.ms_current_time = current_time;
	ms.ms_p_quote_collateral = p_quote_collateral;
	ms.ms_p_qve_report_info = p_qve_report_info;
	ms.ms_p_user_data = p_user_data;
	ms.ms_user_data_size = user_data_size;
	ms.ms_p_verification_result_token_buffer_size = p_verification_result_token_buffer_size;
	ms.ms_p_verification_result_token = p_verification_result_token;
	status = sgx_ecall(eid, 4, &ocall_table_qve, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

