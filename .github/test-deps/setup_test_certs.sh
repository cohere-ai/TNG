#!/usr/bin/env bash
# Copy the AS token-signing certificate chain and root CA to paths tests expect.
#
# Usage:
#   ./setup_test_certs.sh [keys-dir]
#
# If no argument given, defaults to .keys/ (the docker-compose default).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEYS_DIR="${1:-${KEYS_DIR:-${SCRIPT_DIR}/.keys}}"

if [ ! -f "$KEYS_DIR/token-cert-chain.pem" ]; then
    echo "ERROR: $KEYS_DIR/token-cert-chain.pem not found" >&2
    echo "Make sure docker-compose keygen service has completed." >&2
    exit 1
fi

if [ ! -f "$KEYS_DIR/ca-cert.pem" ]; then
    echo "ERROR: $KEYS_DIR/ca-cert.pem not found" >&2
    echo "Make sure docker-compose keygen service has completed." >&2
    exit 1
fi

cp "$KEYS_DIR/token-cert-chain.pem" /tmp/as-full.pem
echo "Copied $KEYS_DIR/token-cert-chain.pem -> /tmp/as-full.pem"

cp "$KEYS_DIR/ca-cert.pem" /tmp/as-ca.pem
echo "Copied $KEYS_DIR/ca-cert.pem -> /tmp/as-ca.pem"
