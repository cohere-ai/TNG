#ifndef QVE_U_H__
#define QVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_qve_header.h"
#include "sgx_qve_def.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __sgx_ql_qve_collateral_t
#define __sgx_ql_qve_collateral_t
typedef struct _sgx_ql_qve_collateral_t {
	uint32_t version;
	uint32_t tee_type;
	char* pck_crl_issuer_chain;
	uint32_t pck_crl_issuer_chain_size;
	char* root_ca_crl;
	uint32_t root_ca_crl_size;
	char* pck_crl;
	uint32_t pck_crl_size;
	char* tcb_info_issuer_chain;
	uint32_t tcb_info_issuer_chain_size;
	char* tcb_info;
	uint32_t tcb_info_size;
	char* qe_identity_issuer_chain;
	uint32_t qe_identity_issuer_chain_size;
	char* qe_identity;
	uint32_t qe_identity_size;
} _sgx_ql_qve_collateral_t;
#endif

#ifndef OCALL_QVT_TOKEN_MALLOC_DEFINED__
#define OCALL_QVT_TOKEN_MALLOC_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_qvt_token_malloc, (uint64_t verification_result_token_buffer_size, uint8_t** p_verification_result_token));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif
#ifndef U_SGXSSL_FTIME_DEFINED__
#define U_SGXSSL_FTIME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_ftime, (void* timeptr, uint32_t timeb_len));
#endif
#ifndef PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
#define PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wait_timeout_ocall, (unsigned long long waiter, unsigned long long timeout));
#endif
#ifndef PTHREAD_CREATE_OCALL_DEFINED__
#define PTHREAD_CREATE_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_create_ocall, (unsigned long long self));
#endif
#ifndef PTHREAD_WAKEUP_OCALL_DEFINED__
#define PTHREAD_WAKEUP_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wakeup_ocall, (unsigned long long waiter));
#endif

sgx_status_t get_fmspc_ca_from_quote(sgx_enclave_id_t eid, quote3_error_t* retval, const uint8_t* quote, uint32_t quote_size, unsigned char* fmsp_from_quote, uint32_t fmsp_from_quote_size, unsigned char* ca_from_quote, uint32_t ca_from_quote_size);
sgx_status_t sgx_qve_get_quote_supplemental_data_size(sgx_enclave_id_t eid, quote3_error_t* retval, uint32_t* p_data_size);
sgx_status_t sgx_qve_get_quote_supplemental_data_version(sgx_enclave_id_t eid, quote3_error_t* retval, uint32_t* p_version);
sgx_status_t sgx_qve_verify_quote(sgx_enclave_id_t eid, quote3_error_t* retval, const uint8_t* p_quote, uint32_t quote_size, const struct _sgx_ql_qve_collateral_t* p_quote_collateral, time_t expiration_check_date, uint32_t* p_collateral_expiration_status, sgx_ql_qv_result_t* p_quote_verification_result, sgx_ql_qe_report_info_t* p_qve_report_info, uint32_t supplemental_data_size, uint8_t* p_supplemental_data);
sgx_status_t tee_qve_verify_quote_qvt(sgx_enclave_id_t eid, quote3_error_t* retval, const uint8_t* p_quote, uint32_t quote_size, time_t current_time, const struct _sgx_ql_qve_collateral_t* p_quote_collateral, sgx_ql_qe_report_info_t* p_qve_report_info, const uint8_t* p_user_data, uint32_t user_data_size, uint32_t* p_verification_result_token_buffer_size, uint8_t** p_verification_result_token);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
