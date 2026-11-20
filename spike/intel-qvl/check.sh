#!/usr/bin/env bash
# Run the verifier on the saved quote and compare every result, supplemental bytes included,
# with what Intel's packaged libsgx_dcap_quoteverify.so produced for the same inputs
# (testdata/expected, captured on x86-64 Linux with libsgx-dcap-quote-verify 1.27.101).
set -euo pipefail
bin=${1:?usage: check.sh <qvl-spike-verify binary>}
cd "$(dirname "$0")/testdata"

# 2026-11-21T00:00:00Z, inside the collateral's validity window, and 2027-01-15T00:00:00Z,
# after it. Fixed rather than "now", so the check keeps passing after the collateral expires.
VALID=1795219200
EXPIRED=1799971200

status=0
run() { # <name> <quote> <time>
  local got
  got=$("$bin" "$2" collateral.json "$3")
  if [ "$got" = "$(cat "expected/$1.json")" ]; then
    echo "ok   $1"
  else
    echo "FAIL $1"
    diff <(echo "$got") "expected/$1.json" || true
    status=1
  fi
}
run valid tdx_quote.dat "$VALID"
run expired tdx_quote.dat "$EXPIRED"
run tampered tdx_quote_tampered.dat "$VALID"
exit $status
