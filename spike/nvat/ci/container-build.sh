#!/usr/bin/env bash
# Build libnvat inside one of the images maturin-action builds the cohere-tng wheels in, with
# that image's compiler and glibc. Expects the repository at /io with fetch-sources.sh
# already run, and an optional Rust target triple to cross-compile for (the
# manylinux_2_28-cross image).
set -euo pipefail
target=${1:-}
cd /io/spike/nvat

if command -v yum >/dev/null 2>&1; then
  # OpenSSL's Configure needs IPC::Cmd, which RPM-based images split out of perl.
  yum install -y -q perl-core perl-IPC-Cmd zlib-devel
fi
if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y -q --default-toolchain none
fi
export PATH=$HOME/.cargo/bin:$PATH
# Installs the repository's pinned toolchain (rust-toolchain.toml), which corrosion builds
# regorus with.
rustup show active-toolchain >/dev/null 2>&1 || rustup show >/dev/null

if [ -n "$target" ]; then
  rustup target add "$target"
  echo "cross: CC=$TARGET_CC CXX=$TARGET_CXX sysroot=$TARGET_SYSROOT"
  # The target's zlib, which libnvat, libxml2 and libcurl link; the sysroot only has glibc.
  if [ ! -f "$TARGET_SYSROOT/usr/include/zlib.h" ]; then
    curl -fsSL https://zlib.net/fossils/zlib-1.3.1.tar.gz | tar -xz -C /tmp
    (cd /tmp/zlib-1.3.1 && CC=$TARGET_CC AR=$TARGET_AR RANLIB=${TARGET_RANLIB:-${TARGET_AR%ar}ranlib} \
      CFLAGS=-fPIC ./configure --prefix=/usr --static && make -j"$(nproc)" && make install DESTDIR="$TARGET_SYSROOT")
  fi
  export STRIP=${TARGET_AR%ar}strip OBJDUMP=${TARGET_AR%ar}objdump
  arch=${target%%-*}
  export NVAT_PATCH=patches/cross-compile.patch
  export NVAT_EXTRA_CMAKE_ARGS="-DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=$arch \
    -DCMAKE_C_COMPILER=$TARGET_CC -DCMAKE_CXX_COMPILER=$TARGET_CXX -DCMAKE_SYSROOT=$TARGET_SYSROOT \
    -DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY \
    -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY -DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY \
    -DRust_CARGO_TARGET=$target -DNVAT_OPENSSL_TARGET=linux-$arch -DNVAT_EP_HOST=$target \
    ${NVAT_EXTRA_CMAKE_ARGS:-}"
fi

./build-libnvat.sh
