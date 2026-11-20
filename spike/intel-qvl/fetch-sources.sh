#!/usr/bin/env bash
# Fetch the Intel sources the -sys build compiles, pinned by commit, into $1, and print the
# environment the build script reads.
set -euo pipefail

dest=${1:?usage: fetch-sources.sh <dir>}
mkdir -p "$dest"
dest=$(cd "$dest" && pwd)

# intel/confidential-computing.tee.dcap, tag DCAP_1.27: the tag Trustee's TDX verifier pins.
DCAP_REV=ecdb68e9854b20d5f6a27cd874f7e89e977e9ca1
# intel/confidential-computing.sgx.sdk, as pinned by intel/linux-sgx tag sgx_2.30, the SGX SDK
# release DCAP 1.27 ships with. Only its public headers (common/inc) are used.
SGX_SDK_REV=73ae8ba0140f9295ef62245897c578c76c289341

fetch() { # <url> <rev> <dir>
  git init -q "$3"
  # A named remote, because the DCAP submodule URLs are relative to it.
  git -C "$3" remote add origin "$1"
  git -C "$3" fetch -q --depth 1 origin "$2"
  git -C "$3" -c advice.detachedHead=false checkout -q FETCH_HEAD
}

fetch https://github.com/intel/confidential-computing.tee.dcap.git "$DCAP_REV" "$dest/dcap"
# Only the submodules the verification library compiles from; the rest (WAMR, PCCS, gtest)
# belong to pieces this build leaves out.
git -C "$dest/dcap" -c protocol.file.allow=never submodule update -q --init --depth 1 \
  QuoteVerification/QVL external/jwt-cpp
fetch https://github.com/intel/confidential-computing.sgx.sdk.git "$SGX_SDK_REV" "$dest/sgx-sdk"

echo "DCAP_SRC_DIR=$dest/dcap"
echo "SGX_SDK_INCLUDE_DIR=$dest/sgx-sdk/common/inc"
