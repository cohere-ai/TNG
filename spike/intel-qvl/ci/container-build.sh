#!/usr/bin/env bash
# Build the verifier inside one of the images maturin-action builds the cohere-tng wheels in,
# with that image's compiler and glibc, and check it when it runs on this host.
#
# Expects the repository at /io and the output of fetch-sources.sh at /intel-src (both
# mounted), and an optional Rust target triple to cross-compile for.
set -euo pipefail
target=${1:-}
cd /io/spike/intel-qvl

if command -v yum >/dev/null 2>&1; then
  # The vendored OpenSSL build needs IPC::Cmd, which RPM-based images split out of perl.
  yum install -y -q perl-core perl-IPC-Cmd
fi
if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y -q --default-toolchain none
fi
export PATH=$HOME/.cargo/bin:$PATH
rustup show active-toolchain >/dev/null 2>&1 || rustup show >/dev/null

echo "compiler: $(${TARGET_CXX:-g++} --version | head -1)"
echo "glibc: $(ldd --version | head -1)"

export DCAP_SRC_DIR=/intel-src/dcap
export SGX_SDK_INCLUDE_DIR=/intel-src/sgx-sdk/common/inc
# No usable libclang in these images.
export QVL_BINDINGS_FILE=$PWD/sys/bindings/linux-glibc.rs
export CARGO_TARGET_DIR=$PWD/target-container

if [ -n "$target" ]; then
  rustup target add "$target"
  cargo build --release -p qvl-spike-verify --features vendored-openssl --target "$target"
  bin=$CARGO_TARGET_DIR/$target/release/qvl-spike-verify
else
  cargo build --release -p qvl-spike-verify --features vendored-openssl
  bin=$CARGO_TARGET_DIR/release/qvl-spike-verify
fi

file "$bin" 2>/dev/null || true
if [ -z "$target" ]; then
  ldd "$bin"
  ./check.sh "$bin"
fi
