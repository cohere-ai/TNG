#!/usr/bin/env bash
# Build the nvat-spike wheel (py/) inside a wheel build image, after container-build.sh, the
# way maturin-action does for cohere-tng: maturin's own auditwheel repair finds libnvat
# through LD_LIBRARY_PATH and copies it into the wheel.
#
# usage: container-wheel.sh <manylinux tag, e.g. 2014 or 2_28> [rust target triple]
set -euo pipefail
tag=${1:?usage: container-wheel.sh <manylinux tag> [target]}
target=${2:-}
cd /io/spike/nvat
export PATH=$HOME/.cargo/bin:$PATH
[ -x "$HOME/.cargo/bin/rustup" ] || curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y -q --default-toolchain none
rustup show active-toolchain >/dev/null 2>&1 || rustup show >/dev/null

# libclang for the -sys crate's bindgen, as co-build-python.yml gets it.
if command -v yum >/dev/null 2>&1; then
  if grep -q 'release 7' /etc/redhat-release 2>/dev/null; then
    yum install -y -q llvm-toolset-7-clang
    export LIBCLANG_PATH=/opt/rh/llvm-toolset-7/root/usr/lib64
    export PATH="$PATH:/opt/rh/llvm-toolset-7/root/usr/bin"
  else
    yum install -y -q clang-devel
  fi
elif command -v apt-get >/dev/null 2>&1; then
  apt-get install -y -qq libclang-dev clang >/dev/null
fi
if [ -n "${TARGET_SYSROOT:-}" ]; then
  export BINDGEN_EXTRA_CLANG_ARGS="--sysroot=$TARGET_SYSROOT"
fi

python=$(command -v python3.12 || command -v python3)
"$python" -m pip install -q 'maturin>=1.9,<2' patchelf
export LD_LIBRARY_PATH=$PWD/vendor/attestation-sdk/nv-attestation-sdk-cpp/build
export CARGO_TARGET_DIR=$PWD/target-wheel
args=(build --release -m py/Cargo.toml -o dist --manylinux "$tag")
if [ -n "$target" ]; then
  rustup target add "$target"
  args+=(--target "$target")
fi
"$python" -m maturin "${args[@]}"
"$python" -m zipfile -l dist/*.whl
