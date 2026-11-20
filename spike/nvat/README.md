# Spike: NVIDIA libnvat built for every cohere-tng wheel target

Throwaway. Can libnvat (NVIDIA attestation-sdk 2026.10.02, libnvat 2.0.0, which upstream
Trustee's NvRemote / NvLocal verifiers link) be built for every cohere-tng wheel target, and
does it verify Trustee's Hopper test evidence the way NVIDIA's own package does?

Results: see the report at the end of this file once CI has run.

```sh
./fetch-sources.sh
./build-libnvat.sh                       # needs cmake, autotools, a Rust toolchain
cargo build --release -p nvat-spike-verify
LD_LIBRARY_PATH=$PWD/vendor/attestation-sdk/nv-attestation-sdk-cpp/build ./check.sh target/release/nvat-spike-verify
```
