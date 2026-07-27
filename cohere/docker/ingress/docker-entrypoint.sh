#!/bin/sh
set -e

TEMPLATE=/etc/tng/conf.template.json
CONFIG=/tmp/tng-conf.json

if [ -z "$TARGET_URL" ]; then
    echo "ERROR: TARGET_URL is required (e.g. https://egress.example.com:443)" >&2
    exit 1
fi

parsed=$(python3 -c '
import os, re
from urllib.parse import urlparse
u = urlparse(os.environ["TARGET_URL"])
scheme = u.scheme or "https"
host = u.hostname or ""
port = u.port or ({"https": 443, "http": 80}.get(scheme, 0))
if not host:
    raise SystemExit("ERROR: could not parse host from TARGET_URL")
if not port:
    raise SystemExit(f"ERROR: cannot infer port from scheme \"{scheme}\"")
# Guard against unexpected characters that could be interpreted by the shell.
for v in (scheme, host, str(port)):
    if not re.fullmatch(r"[A-Za-z0-9._-]+", v):
        raise SystemExit(f"ERROR: invalid value in parsed URL: {v}")
print(f"{scheme}\n{host}\n{port}")
')
OUT_SCHEME=$(echo "$parsed" | sed -n '1p')
OUT_HOST=$(echo "$parsed" | sed -n '2p')
OUT_PORT=$(echo "$parsed" | sed -n '3p')

: "${IN_HOST:=0.0.0.0}"
: "${IN_PORT:=18080}"

export OUT_SCHEME OUT_HOST OUT_PORT IN_HOST IN_PORT
envsubst < "$TEMPLATE" > "$CONFIG"

if [ -n "$POLICY_IDS" ]; then
    tmp=$(mktemp)
    jq --arg pid "$POLICY_IDS" '($pid | split(",")) as $ids |
        .add_ingress[0].verify.policy_ids = $ids
    ' "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG"
fi

if [ -n "$PREDICATE_URL" ]; then
    tmp=$(mktemp)
    jq --arg url "$PREDICATE_URL" --arg bundle "${ATTESTATION_BUNDLE_URL:-}" '
        .add_ingress[0].verify.remote_policy.predicate_url = $url |
        if $bundle != "" then .add_ingress[0].verify.remote_policy.attestation_bundle_url = $bundle else . end
    ' "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG"
fi

exec tng launch --config-file "$CONFIG" "$@"
