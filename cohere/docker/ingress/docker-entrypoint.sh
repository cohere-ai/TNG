#!/bin/sh
set -e

TEMPLATE=/etc/tng/conf.template.json
CONFIG=/tmp/tng-conf.json

if [ -z "$TARGET_URL" ]; then
    echo "ERROR: TARGET_URL is required (e.g. https://egress.example.com:443)" >&2
    exit 1
fi

eval "$(python3 -c "
from urllib.parse import urlparse
u = urlparse('$TARGET_URL')
scheme = u.scheme or 'https'
host = u.hostname or ''
port = u.port or ({'https': 443, 'http': 80}.get(scheme, 0))
if not host:
    raise SystemExit('ERROR: could not parse host from TARGET_URL=$TARGET_URL')
if not port:
    raise SystemExit(f'ERROR: cannot infer port from scheme \"{scheme}\", specify port in TARGET_URL')
print(f'OUT_SCHEME={scheme}')
print(f'OUT_HOST={host}')
print(f'OUT_PORT={port}')
")"

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

exec tng launch --config-file "$CONFIG" "$@"
