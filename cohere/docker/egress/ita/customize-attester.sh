#!/bin/sh
# Injects ITA policy ids into the attester and the peer verifier.
set -e

CONFIG="$1"

if [ -z "$POLICY_IDS" ]; then
    exit 0
fi

tmp=$(mktemp)
jq --arg pid "$POLICY_IDS" '($pid | split(",")) as $ids |
    (.add_egress[].ohttp.key.attest.policy_ids) = $ids |
    (.add_egress[].ohttp.key.verify.policy_ids) = $ids |
    (.add_egress[].attest.policy_ids) = $ids
' "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG"
