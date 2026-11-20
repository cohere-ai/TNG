#!/usr/bin/env bash
# Verify Trustee's Hopper CoCo test evidence (deps/verifier/test_data/nvidia/hopper_coco_*1.txt
# in cohere-ai/trustee, the remote_verifier_coco case) through the given libnvat build, with
# NvRemote (live NRAS) and NvLocal (live RIM service and OCSP, checked in-process).
#
# Writes the normalized results to out/<mode>.json for comparison with NVIDIA's package.
set -euo pipefail
bin=${1:?usage: check.sh <nvat-spike-verify binary>}
bin=$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")
cd "$(dirname "$0")"
mkdir -p out

# Trustee's test passes 48 bytes of report data; the verifier truncates it to the 32-byte
# SPDM nonce (regularize_data), which is what the evidence carries.
NONCE=87d8e24ab336adafe228d49e83d745f6dba4ae505372b6a5704820856b343fec
CERTS=testdata/hopper_coco_certs1.txt
# The saved report has one byte after the SPDM response. Trustee's own Local/Remote
# verifiers ignore it; libnvat counts it in and then rejects the signature (NVAT error 508,
# NRAS 4013 INVALID_EVIDENCE_SIGNATURE), NVIDIA's package included. Check both.
tr -d '\n' < testdata/hopper_coco_report1.txt > out/report-as-saved.txt
sed 's/00$//' out/report-as-saved.txt > out/report.txt

status=0
for mode in remote local; do
  for attempt in default ca; do
    if [ $attempt = ca ]; then
      # Only reached when the default CA setup failed: say whether naming a bundle fixes it.
      for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
        [ -f "$f" ] && export NVAT_SPIKE_TLS_CA_CERT=$f && break
      done
      echo "     retrying $mode with NVAT_SPIKE_TLS_CA_CERT=$NVAT_SPIKE_TLS_CA_CERT"
    fi
    start=$(date +%s)
    if "$bin" $mode out/report.txt $CERTS $NONCE > out/$mode.json 2> out/$mode.log; then
      echo "ok   $mode ($attempt CA setup, $(($(date +%s) - start))s): $(grep -m1 '"message"' out/$mode.json)"
      [ $attempt = ca ] && status=1 && echo "FAIL $mode only works with an explicit CA bundle"
      break
    fi
    echo "FAIL $mode ($attempt CA setup):"
    grep -vE 'cert\[|\(base64\)|\[debug\]' out/$mode.log | tail -15
    cat out/$mode.json
    if [ $attempt = ca ] || ! grep -qiE 'ssl|certificate|curl' out/$mode.log; then
      status=1
      break
    fi
  done
  unset NVAT_SPIKE_TLS_CA_CERT

  if "$bin" $mode out/report-as-saved.txt $CERTS $NONCE > /dev/null 2> out/$mode-as-saved.log; then
    echo "FAIL $mode accepted the report with the stray byte"
    status=1
  elif grep -q 'Error 508' out/$mode-as-saved.log; then
    echo "ok   $mode rejects the report as saved (stray byte): $(tail -1 out/$mode-as-saved.log)"
  else
    echo "FAIL $mode rejected the report as saved, but not with error 508:"
    tail -5 out/$mode-as-saved.log
    status=1
  fi
done
exit $status
