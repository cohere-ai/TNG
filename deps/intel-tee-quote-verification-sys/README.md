# intel-tee-quote-verification-sys, built from source

Trustee's TDX verifier reaches Intel's quote verification library through
`intel-tee-quote-verification-rs`, whose FFI crate, `intel-tee-quote-verification-sys`, links
`libsgx_dcap_quoteverify`. Intel packages that library for x86-64 Linux only, so the TDX
verifier could not build for the macOS and aarch64 Linux cohere-tng wheels.

`generated/` is Intel's crate with a few patches, which compiles the library from Intel's
source and links it statically. The root `Cargo.toml` swaps it in for the crates.io release
with `[patch.crates-io]`; nothing in Trustee changes.

| | |
|---|---|
| Upstream | https://github.com/intel/confidential-computing.tee.dcap, `QuoteVerification/dcap_quoteverify/sgx-dcap-quoteverify-sys` |
| Revision | `DCAP_1.27`, `ecdb68e9854b20d5f6a27cd874f7e89e977e9ca1` (identical to crates.io 0.3.0) |
| License | BSD-3-Clause (Intel); the compiled-in RapidJSON and jwt-cpp are MIT. Texts in `generated/licenses/` |

## Local modifications

All of them are in `patches/`, applied in the order `patches/series` lists:

1. `0001` stubs out the calls into SGX enclaves: the Quote Verification Enclave bridge, which
   Intel's build generates with an SGX SDK tool, and the appraisal engine's QAE loader. They are
   only ever reached on SGX hardware, on request.
2. `0002` links OpenSSL through `openssl-sys`, so the library shares the process's OpenSSL.
3. `0003` rewrites `build.rs` to fetch Intel's sources with git at pinned commits and compile
   them, following Intel's Linux Makefile.

Intel's C and C++ sources are never modified; they are fetched at build time. Building needs
git, network access to GitHub, a C++17 compiler, and libclang for bindgen.

## Updating

Never edit `generated/`. Change the patches, then run `./update.sh`, which rebuilds
`generated/` from Intel's crate at the pinned commit plus the series. CI runs it too and fails
if `generated/` would change.

To edit a patch, `./update.sh --keep /tmp/qvl` leaves a git repository with Intel's crate as the
first commit and one commit per patch. Amend or rebase there, then export the series again
(the command is in `update.sh`).

To move to a new DCAP release:

1. Update `DCAP_REV` in `update.sh`, and the matching `rev` constants in patch `0003`'s
   `build.rs` (the SGX SDK one too, if the release moves to a new SGX SDK).
2. Run `./update.sh` and resolve any patch that no longer applies.
3. Compare the source list in `build.rs` with the release's
   `QuoteVerification/dcap_quoteverify/linux/Makefile`, and `stubs/linux/qve_u.h` with the
   calls its `ae/QvE/qve/qve.edl` declares.
