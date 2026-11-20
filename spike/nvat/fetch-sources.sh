#!/usr/bin/env bash
# Fetch NVIDIA's attestation SDK at the tag upstream Trustee pins (2026.10.02, libnvat 2.0.0)
# into vendor/attestation-sdk, where the verifier's path dependencies and the -sys crate's
# "local C++ build" mode expect it.
set -euo pipefail
cd "$(dirname "$0")"

NVSDK_REV=11b2bfeb42a1158aa08744603ecb239ccb3d2265 # tag 2026.10.02
dest=vendor/attestation-sdk

if [ "$(git -C "$dest" rev-parse HEAD 2>/dev/null || true)" = "$NVSDK_REV" ]; then
  exit 0
fi
rm -rf "$dest"
git init -q "$dest"
git -C "$dest" remote add origin https://github.com/NVIDIA/attestation-sdk.git
git -C "$dest" fetch -q --depth 1 origin "$NVSDK_REV"
git -C "$dest" -c advice.detachedHead=false checkout -q FETCH_HEAD
