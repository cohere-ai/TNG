# tng-ingress

Pre-configured TNG ingress image for encrypting traffic to a Cohere TNG egress endpoint.

Published to `ghcr.io/cohere-ai/tng-ingress`.

## Quick start

```sh
docker run -e TARGET_URL=https://egress.example.com ghcr.io/cohere-ai/tng-ingress
```

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `TARGET_URL` | Yes | — | URL of the TNG egress endpoint. Scheme, host, and port are parsed from this. |
| `IN_HOST` | No | `0.0.0.0` | Listen address for the ingress proxy. |
| `IN_PORT` | No | `18080` | Listen port for the ingress proxy. |
| `POLICY_IDS` | No | `cbeedffa-e224-4664-b6b4-573fcd4133d3` | Comma-separated ITA attestation policy IDs. |
