# Spike: Intel QVL built from source

Can Trustee's TDX verifier ship in the cohere-tng wheel on every target (Linux x86-64 and
aarch64, macOS x86-64 and arm64) while still using Intel's own quote verification library?

Intel only packages `libsgx_dcap_quoteverify` for x86-64 Linux and Windows, and the crates.io
`intel-tee-quote-verification-sys` just links that installed library. `sys/` is a fork of that
crate (same version, 0.3.0, same bindgen setup) whose build script compiles the library from
Intel's DCAP source instead, statically, against the process's OpenSSL. `verify/` calls it
through `intel-tee-quote-verification-rs` at `DCAP_1.27`, exactly as Trustee does.

What gets compiled mirrors `QuoteVerification/dcap_quoteverify/linux/Makefile`, minus the QAL
appraisal engine and its WAMR runtime, which `tee_verify_quote` does not use. Two pieces come
from outside the DCAP tree:

- `sys/generated/linux/qve_u.{c,h}`: the untrusted bridge to the QvE enclave, which Intel's
  build generates with `sgx_edger8r`. Generated with the SGX SDK 2.30.100.1 installer's
  `sgx_edger8r --untrusted ae/QvE/qve/qve.edl`, with the SDK's include dir and intel-sgx-ssl
  `3.0_Rev5.4`'s `sgx_tsgxssl.edl` and `nofilefunc/sgxssl_file.edl` on the search path. Only
  used when an SGX QvE enclave can be loaded, which it never can off SGX hardware.
- `sys/shim/sgxssl_ocalls.cpp`: the one SGX-SSL ocall that bridge references, normally from
  `libsgx_usgxssl.a`.

## The check

`testdata/tdx_quote.dat` is a TDX quote from a GCP TDX guest, and `collateral.json` its Intel
PCS collateral, fetched 2026-11-20. `check.sh` verifies it at a fixed time inside the
collateral's validity, at one after it, and a copy with one byte of the TD report flipped, and
compares the JSON output, raw supplemental data included, with `testdata/expected/`. Those
files are the output of Intel's packaged library (`libsgx-dcap-quote-verify` 1.27.101,
Ubuntu 24.04), which the `baseline-intel-package` CI job re-checks.

```sh
./fetch-sources.sh /tmp/intel-src > /tmp/intel-src.env
set -a; . /tmp/intel-src.env; set +a
cargo build --release -p qvl-spike-verify --features vendored-openssl
./check.sh target/release/qvl-spike-verify
```
