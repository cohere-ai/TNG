// Untrusted half of the one SGX-SSL ocall the QvE EDL imports. Intel ships it in
// libsgx_usgxssl.a (intel-sgx-ssl, Linux/sgx/libsgx_usgxssl/ufile.cpp); it is only reached
// when the QvE enclave runs, which never happens off SGX hardware, but qve_u.c's ocall
// table references it, so it has to link.
#include <stdint.h>
#include <string.h>
#include <sys/timeb.h>

extern "C" void u_sgxssl_ftime(void *timeptr, uint32_t timeb_len)
{
    if (timeptr == nullptr || timeb_len != sizeof(struct timeb)) {
        return;
    }
    ftime(static_cast<struct timeb *>(timeptr));
}
