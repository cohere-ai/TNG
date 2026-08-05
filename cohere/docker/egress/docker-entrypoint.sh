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

if [ -n "$PEERS" ]; then
    tmp=$(mktemp)
    jq --arg peers "$PEERS" '
        (.add_egress[].ohttp.key.peers) = ($peers | split(","))
    ' "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG"
fi

if [ -n "$TNG_METRIC_OTLP_ENDPOINT" ]; then
    case "$TNG_METRIC_OTLP_ENDPOINT" in
        http://127.0.0.1:*|http://opentelemetry-collector.opentelemetry.svc.cluster.local:4317|https://*)
            ;;
        *)
            echo "Unsupported TNG_METRIC_OTLP_ENDPOINT" >&2
            exit 1
            ;;
    esac

    tmp=$(mktemp)
    jq --arg endpoint "$TNG_METRIC_OTLP_ENDPOINT" '
        .metric.exporters = ((.metric.exporters // []) + [{
            "type": "oltp",
            "protocol": "grpc",
            "headers": null,
            "endpoint": $endpoint,
            "step": 30
        }])
    ' "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG"
fi

exec tng launch --config-file "$CONFIG" "$@"
