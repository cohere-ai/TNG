#!/bin/sh
set -e

MOUNTED=/etc/tng/conf.json
DEFAULT=/etc/tng/conf.default.json
CONFIG=/tmp/tng-conf.json

if [ -f "$MOUNTED" ]; then
    echo "Using mounted config at $MOUNTED"
    cp "$MOUNTED" "$CONFIG"
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

if [ -n "$PREDICATE_URL" ]; then
    tmp=$(mktemp)
    jq --arg url "$PREDICATE_URL" --arg bundle "${ATTESTATION_BUNDLE_URL:-}" '
        (.add_egress[].ohttp.key.attest.remote_policy.predicate_url) = $url |
        (.add_egress[].ohttp.key.verify.remote_policy.predicate_url) = $url |
        (.add_egress[].attest.remote_policy.predicate_url) = $url |
        if $bundle != "" then
            (.add_egress[].ohttp.key.attest.remote_policy.attestation_bundle_url) = $bundle |
            (.add_egress[].ohttp.key.verify.remote_policy.attestation_bundle_url) = $bundle |
            (.add_egress[].attest.remote_policy.attestation_bundle_url) = $bundle
        else . end
    ' "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG"
fi

if [ -n "$PEERS" ]; then
    tmp=$(mktemp)
    jq --arg peers "$PEERS" '
        (.add_egress[].ohttp.key.peers) = ($peers | split(","))
    ' "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG"
fi

exec tng launch --config-file "$CONFIG" "$@"
