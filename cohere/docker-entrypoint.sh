#!/bin/sh
set -e

CONFIG=/etc/tng/conf.json
DEFAULT=/etc/tng/conf.default.json

if [ -f "$CONFIG" ]; then
    echo "Using mounted config at $CONFIG"
else
    echo "No mounted config found, using default"
    cp "$DEFAULT" "$CONFIG"
fi

if [ -n "$POLICY_IDS" ]; then
    tmp=$(mktemp)
    jq --arg pid "$POLICY_IDS" '($pid | split(",")) as $ids |
        (.add_egress[].ohttp.key.attest.policy_ids) = $ids |
        (.add_egress[].ohttp.key.verify.policy_ids) = $ids |
        (.add_egress[].attest.policy_ids) = $ids
    ' "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG"
fi

if [ -n "$PEERS" ]; then
    tmp=$(mktemp)
    jq --arg peers "$PEERS" '
        (.add_egress[].ohttp.key.peers) = ($peers | split(","))
    ' "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG"
fi

exec tng launch --config-file "$CONFIG"
