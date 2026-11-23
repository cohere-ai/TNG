// Stands in for tee_qae_get_target_info() from QuoteVerification/appraisal/qal/appraisal.cpp,
// part of the QAL appraisal engine this crate leaves out. The real function loads the Quote
// Appraisal Enclave (QAE) for tee_verify_quote_qvt(); off SGX hardware that load fails, and this
// fails the same way. Defined so the library is complete without relying on the linker to drop
// tee_verify_quote_qvt(), which nothing here calls.
#include "qal_common.h"

quote3_error_t tee_qae_get_target_info(sgx_target_info_t *p_target_info)
{
    (void)p_target_info;
    return SGX_QL_ERROR_UNEXPECTED;
}
