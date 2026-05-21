#!/bin/sh
set -e

TEMPLATE=/etc/tng/config.template.json
CONFIG=/etc/tng/config.json

if [ -n "$POLICY_ID" ]; then
    jq --arg pid "$POLICY_ID" '
        (.add_egress[].ohttp.key.attest.policy_ids) = [$pid] |
        (.add_egress[].ohttp.key.verify.policy_ids) = [$pid] |
        (.add_egress[].attest.policy_ids) = [$pid]
    ' "$TEMPLATE" > "$CONFIG"
else
    jq '
        (.add_egress[].ohttp.key.attest.policy_ids) = [] |
        (.add_egress[].ohttp.key.verify.policy_ids) = [] |
        (.add_egress[].attest.policy_ids) = []
    ' "$TEMPLATE" > "$CONFIG"
fi

exec tng launch --config-file "$CONFIG" "$@"
