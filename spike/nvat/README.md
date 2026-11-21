# Spike: NVIDIA libnvat built for every cohere-tng wheel target

Throwaway, like `spike/intel-qvl`. Can libnvat (NVIDIA attestation-sdk tag 2026.10.02,
libnvat 2.0.0, what upstream Trustee's NvRemote / NvLocal verifiers link) be built for every
cohere-tng wheel target, and does it verify Trustee's Hopper test evidence the way NVIDIA's
own package does?

**Yes, on all four targets.** CI run:
https://github.com/cohere-ai/TNG/actions/runs/44846675574 (all jobs green).

## Results

Every source build verifies `hopper_coco_report1.txt` + `hopper_coco_certs1.txt` (nonce
`87d8e24a…3fec`, as in Trustee's `remote_verifier_coco` case) through live NRAS (NvRemote)
and in-process against the live RIM service and OCSP (NvLocal), with Trustee's own call
sequence (`verify/src/lib.rs` mirrors `deps/verifier/src/nvidia/nvat.rs`). The verdict and
every claim, per-request fields aside (iat, exp, nbf, jti, the device token digest), match
NVIDIA's x86-64 package byte for byte. Each build also verified from an installed wheel.

| target | builds in | NvRemote | NvLocal | CA bundle by default | clean build¹ | libnvat (stripped) | wheel |
|---|---|---|---|---|---|---|---|
| macOS arm64, min 11.0 | macos-15 | pass, same claims | pass, same claims | yes | 6m02s | 23.1 (19.0) MiB | `macosx_11_0_arm64`, delocate |
| macOS x86-64, min 10.12 | macos-15-intel | pass, same claims | pass, same claims | yes | 15m39s | 23.6 (19.5) MiB | `macosx_10_12_x86_64`, delocate |
| Linux x86-64 | manylinux2014 (GCC 10) | pass, same claims | pass, same claims | no² | 6m51s | 32.1 (24.1) MiB | `manylinux2014_x86_64`, maturin |
| Linux aarch64, native | manylinux_2_28 on ubuntu-24.04-arm (GCC 14) | pass, same claims | pass, same claims | no² | 6m57s | 31.4 (22.5) MiB | `manylinux_2_28_aarch64`, maturin |
| Linux aarch64, cross | manylinux_2_28-cross (GCC 7.5), run on ubuntu-24.04-arm | pass, same claims | pass, same claims | no² | 4m39s | 30.3 (22.1) MiB | `manylinux_2_28_aarch64`, maturin |
| NVIDIA package x86-64 | apt, cuda ubuntu2404 repo | pass | pass | yes | – | 25.6 MiB (shipped stripped) | – |
| NVIDIA package aarch64 | apt, cuda ubuntu2404 sbsa repo | pass, same claims | pass, same claims | yes | – | 24.4 MiB | – |

¹ `build-libnvat.sh` wall time with `NVAT_JOBS=2`: CMake configure, fetching its
FetchContent dependencies, OpenSSL, libxml2, xmlsec, curl, regorus and libnvat.
² See "CA bundle" below.

Symbol versions needed: manylinux2014 build GLIBC_2.17 / GLIBCXX_3.4.19 / CXXABI_1.3.7,
the manylinux_2_28 builds GLIBC_2.28. NVIDIA's own x86-64 package needs GLIBC_2.28 (it is
built on RHEL 8), so it could not go into a manylinux2014 wheel as is. macOS builds carry
`minos 11.0` / `LC_VERSION_MIN_MACOSX 10.12`.

## Fixes each target needed

None touches NVIDIA's sources. The only patch to their build is for cross-compiling.

All targets:

- **Autotools.** libxml2's build reruns autoconf, which fails if it isn't installed. Probably
  because the tarball is extracted with fresh timestamps (NVIDIA sets CMP0135 NEW), so make
  thinks `configure` is stale. The manylinux images
  have autotools; macOS needs `brew install autoconf automake libtool`, the cross image
  `apt-get install autoconf automake libtool`.
- **Parallelism.** One compile job per core runs out of memory: the native aarch64 job was
  killed (16 GB runner), macOS arm64 (7 GB) took 45 minutes instead of 7. No single file is
  big (0.8 GB peak per file with GCC 13); the cause is the nesting, since every ExternalProject
  runs its own `make -j<cores>` and regorus a full cargo build, alongside CMake's own jobs.
  `NVAT_JOBS=2` (`cmake --build --parallel 2`) fixes it.

macOS:

- **Link flags** (both): NVIDIA's CMake lists the static dependencies' link libraries for
  Linux only. libcurl also needs `-framework CoreFoundation -framework SystemConfiguration`
  and libxml2 `-liconv`, passed through `CMAKE_SHARED_LINKER_FLAGS`.
- **Homebrew's OpenSSL** (Intel only): its headers are in `/usr/local/include/openssl`, which
  Apple clang searches ahead of curl's `-isystem` for the built OpenSSL, so curl compiled
  with ENGINE support against the no-engine libcrypto and failed to link. Moving Homebrew's
  headers away fixes it; on a release machine, build with no Homebrew OpenSSL linked.

manylinux2014 (GCC 10): GCC 10 warns `-Wstringop-overflow` in fmt 10.2.1 and NVIDIA's CMake
makes warnings errors: `-DCMAKE_COMPILE_WARNING_AS_ERROR=OFF`.

manylinux_2_28 native aarch64: nothing beyond the above.

manylinux_2_28-cross aarch64 (`patches/cross-compile.patch`, 20 lines of CMake, plus flags in
`ci/container-build.sh`):

- The ExternalProjects never get a target: the patch passes `--host` and the target's
  `AR`/`RANLIB` to the autoconf ones and a target (`linux-aarch64`) to OpenSSL's Configure.
- `-fmacro-prefix-map`, which NVIDIA adds for every GCC, only exists from GCC 8; the image
  has 7.5. The patch adds it only for GCC 8+ (it only shortens `__FILE__` in log lines).
- The usual cross CMake flags, `-DRust_CARGO_TARGET` for corrosion, warnings-as-errors off,
  a static zlib for the target in the sysroot (the image has none), and `pkg-config`.

Building aarch64 natively on ubuntu-24.04-arm in `manylinux_2_28_aarch64` needs none of the
cross work and is the simpler choice for the wheel workflow.

## CA bundle

Trustee creates libnvat's HTTP options without a CA file, so libcurl uses the bundle path its
configure found on the build machine. For the manylinux builds that is RHEL's
`/etc/pki/tls/certs/ca-bundle.crt`, which Debian and Ubuntu don't have; cross-compiled there
is none. Every NRAS, RIM and OCSP request then fails TLS. Naming the system bundle through
`HttpOptions::tls_ca_cert` fixes it (the CI retries with the first of the usual locations that
exists, `NVAT_SPIKE_TLS_CA_CERT=auto`). macOS builds find `/etc/ssl/cert.pem`, which every
Mac has. NVIDIA's packages are built for the distribution they ship in.

So the integration has to set the CA file: probe the usual locations at runtime (what
openssl-probe does) in Trustee's `build_http_options`, which needs a small change in our
Trustee fork. An alternative is building curl with `--with-ca-embed`, which ties the trust
store to the wheel release.

## Shared or static

Ship libnvat as its own shared library inside the wheel, linked with only `nvat_*` exported.

- NVIDIA's link exports everything: 17,000-20,000 dynamic symbols, among them about 3,700
  from OpenSSL 3.6.4, 2,100 from libxml2/xmlsec and 4,900 Rust symbols (regorus' std). NVIDIA's
  own package is the same (20,397). In a Python process another extension or library could
  bind to those OpenSSL symbols, or libnvat's to theirs.
- A version script (`exports/nvat.map`, `-Wl,--version-script,...`, `-Wl,--exclude-libs,ALL`)
  or on macOS `-exported_symbols_list` with `_nvat_*` cuts that to exactly the 134 `nvat_*`
  functions on every target, with no source change. The relink takes seconds, and both
  verifiers still pass with it.
- Static linking into the cohere-tng extension (not tried) would put a second OpenSSL (the
  verifiers already link `openssl/vendored`) and a second Rust standard library (regorus is a
  Rust staticlib) into one link. That means duplicate-symbol errors or one copy silently
  replacing the other, and NVIDIA's build has no switch for it. The shared library keeps both
  private.

## Shipping it in the wheel

`py/` is a stand-in for the cohere-tng extension (pyo3 0.29, abi3-py38, as cohere-tng), built
and repaired the way the real workflow builds its wheels:

- Linux: maturin, run in the manylinux image with `LD_LIBRARY_PATH` pointing at libnvat, finds
  the dependency itself and copies it into `nvat_spike.libs/libnvat-<hash>.so.2` with an
  rpath (needs `patchelf`). The tags came out `manylinux2014_x86_64` and `manylinux_2_28_aarch64`,
  cross-built included. libz.so.1 is allowed by the manylinux policies and not bundled; the
  cross build links zlib statically.
- macOS: maturin does not bundle; `delocate-wheel` copies libnvat into `.dylibs/` and rewrites
  the install name to `@loader_path/.dylibs/`, keeping the wheel's 11.0 / 10.12 tags.
- Each wheel installed into a fresh venv, with nothing on the library path, gives the same
  verdicts and claims as the binary.

Each wheel grows by about 20-25 MB if libnvat is stripped. On Linux maturin bundles it as
built (32 MiB), so strip it before the wheel build.

## Also found

- The saved `hopper_coco_report1.txt` has one byte after the SPDM response. Trustee's
  existing Local and Remote verifiers ignore it; libnvat counts it in and reports an invalid
  signature (NVAT error 508, NRAS 4013), and so does NVIDIA's package. Without it, everything
  passes. `check.sh` checks both. Before switching, confirm TNG's attester never sends
  trailing bytes.
- nv-attestation-sdk-sys can only link a library in `../nv-attestation-sdk-cpp/build` or an
  installed one with its header at the hard-coded `/usr/include/nvat.h`, which isn't writable
  on macOS. Building against a cargo git checkout as Trustee depends on it needs a small fork
  of that build script (e.g. `NVAT_LIB_DIR` / `NVAT_INCLUDE_DIR`).
- Upstream gates NVAT to `target_arch = "x86_64"` only because of its Dockerfile; NVIDIA's
  sbsa apt repo has libnvat 2.0.0 for arm64 too, and gives the same claims.

## Running it

```sh
./fetch-sources.sh                       # NVIDIA's SDK at 2026.10.02 into vendor/
NVAT_JOBS=2 ./build-libnvat.sh           # needs cmake, autotools, the repository's Rust
cargo build --release -p nvat-spike-verify
LD_LIBRARY_PATH=$PWD/vendor/attestation-sdk/nv-attestation-sdk-cpp/build \
  ./check.sh target/release/nvat-spike-verify
```

`build-libnvat.sh` leaves the restricted library in the SDK's `build/` and writes export
tables, sizes and the build time to `out/`. `check.sh` writes both verdicts there;
`ci/compare.sh` turns a run's artifacts into the table above.
