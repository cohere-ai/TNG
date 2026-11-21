#!/usr/bin/env bash
# Build libnvat from NVIDIA's CMake project with this host's toolchain, into the
# nv-attestation-sdk-cpp/build directory the -sys crate's local-build mode links from.
#
# Linked twice: once exactly as NVIDIA's CMake does (every symbol of every bundled library
# exported), once with only nvat_* exported, which is what a wheel would ship. Both export
# tables are recorded in out/; the restricted library is the one left in build/.
#
# Env:
#   NVAT_EXTRA_CMAKE_ARGS  extra configure arguments (per-target fixes), word-split
#   NVAT_PATCH             patch to apply to the SDK before configuring (cross builds)
#   NVAT_JOBS              parallel compile jobs (default: one per core)
set -euo pipefail
cd "$(dirname "$0")"
spike=$PWD
src=$spike/vendor/attestation-sdk/nv-attestation-sdk-cpp
build=$src/build
out=$spike/out
mkdir -p "$out"

os=$(uname -s)
if [ -n "${NVAT_PATCH:-}" ]; then
  if git -C "$spike/vendor/attestation-sdk" apply --check -R "$spike/$NVAT_PATCH" 2>/dev/null; then
    echo "$NVAT_PATCH already applied"
  else
    git -C "$spike/vendor/attestation-sdk" apply "$spike/$NVAT_PATCH"
  fi
fi

echo "cmake: $(cmake --version | head -1)"
echo "cc: $(${CC:-cc} --version | head -1)"
echo "rustc: $(rustc --version)"
[ "$os" = Linux ] && echo "glibc: $(ldd --version | head -1)"
[ "$os" = Darwin ] && echo "MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-unset}"

if [ "$os" = Darwin ]; then
  restrict="-Wl,-exported_symbols_list,$spike/exports/nvat.exp"
  lib=$build/libnvat.dylib
else
  # --exclude-libs keeps the static archives' symbols out of the dynamic table even where
  # the version script alone would not (e.g. symbol versions they carry themselves).
  restrict="-Wl,--version-script=$spike/exports/nvat.map -Wl,--exclude-libs,ALL"
  lib=$build/libnvat.so
fi

platform=()
if [ "$os" = Darwin ]; then
  # NVIDIA's CMake hardcodes the static libraries' link dependencies for Linux. On macOS
  # libcurl also needs CoreFoundation and SystemConfiguration, and libxml2 libiconv.
  platform_ldflags="-framework CoreFoundation -framework SystemConfiguration -liconv"
  # Homebrew's OpenSSL headers are in /usr/local/include on Intel Macs, which the compiler
  # searches by default, so curl compiled against them (ENGINE on) and then failed to link
  # the no-engine libcrypto NVIDIA builds. Put the built headers first (a no-op on arm64,
  # where Homebrew is in /opt/homebrew).
  platform+=("-DCMAKE_C_FLAGS=-I$build/openssl-install/include")
else
  platform_ldflags=""
fi

configure() { # <shared linker flags>
  # shellcheck disable=SC2086
  cmake -S "$src" -B "$build" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
    "-DCMAKE_SHARED_LINKER_FLAGS=$platform_ldflags $1" ${platform[@]+"${platform[@]}"} \
    ${NVAT_EXTRA_CMAKE_ARGS:-}
}

start=$(date +%s)
configure ""
# Some of libnvat's sources (the generated CBOR decoders' users) take several GB each to
# compile, so one job per core can run out of memory; NVAT_JOBS caps it.
cmake --build "$build" --parallel ${NVAT_JOBS:-}
end=$(date +%s)
echo "$((end - start))" > "$out/build-seconds"
echo "full build: $((end - start))s"

exports() { # <lib> <file>
  if [ "$os" = Darwin ]; then
    nm -gU "$1" | awk '{print $3}' | sed 's/^_//' | sort > "$2"
  else
    nm -D --defined-only "$1" | awk '{print $3}' | sort > "$2"
  fi
}
summary() { # <exports file>
  # Rust symbols: legacy mangling ends in a 17h<hash>E, plus regorus' own C entry points.
  printf 'total=%s nvat_=%s openssl=%s curl=%s libxml2/xmlsec=%s rust=%s c++=%s\n' \
    "$(wc -l < "$1")" "$(grep -c '^nvat_' "$1" || true)" \
    "$(grep -cE '^(SSL|EVP|OPENSSL|CRYPTO|X509|BIO|ERR|RSA|EC|BN|ASN1|PEM|OSSL)_' "$1" || true)" \
    "$(grep -c '^curl_' "$1" || true)" "$(grep -cE '^(xml|xmlSec|html)' "$1" || true)" \
    "$(grep -cE 'regorus|17h[0-9a-f]{16}E$|^_R|^rust_' "$1" || true)" \
    "$(grep -E '^_Z' "$1" | grep -cvE '17h[0-9a-f]{16}E$' || true)"
}
exports "$lib" "$out/exports-default.txt"
echo "exports as NVIDIA links it: $(summary "$out/exports-default.txt")"

start=$(date +%s)
configure "$restrict"
cmake --build "$build" --parallel --target nvat
echo "relink with restricted exports: $(($(date +%s) - start))s"
exports "$lib" "$out/exports-restricted.txt"
echo "exports restricted: $(summary "$out/exports-restricted.txt")"

real=$(basename "$(find "$build" -maxdepth 1 -type f \( -name 'libnvat.so.*.*.*' -o -name 'libnvat.*.*.*.dylib' \) | head -1)")
ls -l "$build"/libnvat*
stripped=$out/stripped-$real
if [ "$os" = Darwin ]; then strip -x -o "$stripped" "$build/$real"; else strip -o "$stripped" "$build/$real"; fi
{
  echo "file=$real"
  echo "size=$(wc -c < "$build/$real" | tr -d ' ')"
  echo "stripped_size=$(wc -c < "$stripped" | tr -d ' ')"
} > "$out/size"
rm -f "$stripped"
cat "$out/size"
file "$build/$real"
if [ "$os" = Darwin ]; then
  otool -L "$build/$real"
  otool -l "$build/$real" | grep -A4 -E 'LC_BUILD_VERSION|LC_VERSION_MIN_MACOSX'
else
  readelf -d "$build/$real" | grep -E 'NEEDED|SONAME|RPATH|RUNPATH'
  echo "glibc/libstdc++ symbol versions needed (newest):"
  objdump -T "$build/$real" | grep -oE '(GLIBC|GLIBCXX|CXXABI)_[0-9.]+' | sort -Vu \
    | awk -F_ '{v[$1]=$0} END {for (k in v) print "  " v[k]}'
fi
