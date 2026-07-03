# conseel

Drop-in encrypted transport for AI SDKs. Wraps [cohere-tng](https://pypi.org/project/cohere-tng/) to route
requests through OHTTP encryption with TEE attestation verification. TNG
automatically promotes the `model` field from JSON request bodies into an
`x-gateway-model-name` header for backend routing (via `body_field_headers`
config).

## Install

```bash
pip install conseel
```

## Usage

### Cohere

```python
import cohere
import httpx
from conseel import Transport

co = cohere.ClientV2(
    api_key="...",
    httpx_client=httpx.Client(transport=Transport()),
)
co.chat(model="command-a-plus-05-2026", messages=[...])
```

### OpenAI

```python
from openai import OpenAI
import httpx
from conseel import Transport

client = OpenAI(
    http_client=httpx.Client(transport=Transport()),
)
client.chat.completions.create(model="gpt-4", messages=[...])
```

### Async

```python
import httpx
from conseel import AsyncTransport

async with httpx.AsyncClient(transport=AsyncTransport()) as client:
    resp = await client.post(url, json={"model": "command-a-plus-05-2026", ...})
```

## What it does

1. **Encrypts** all traffic via OHTTP so that even the network infrastructure
   cannot inspect request or response payloads.
2. **Verifies** the remote TEE via Intel Trust Authority attestation before
   sending any data (configurable via the `verify` parameter).
3. **Promotes** the `model` field from JSON request bodies to the
   `x-gateway-model-name` HTTP header for gateway routing. This happens
   inside TNG via `body_field_headers` config. Body parsing is skipped
   entirely for non-JSON requests (e.g. multipart audio uploads) and
   when the target headers are already present on the request.
4. **Forwards** `authorization` and `x-gateway-model-name` headers through the
   OHTTP layer to the backend.

## Configuration

`Transport` and `AsyncTransport` accept the same `verify` and `ohttp` keyword
arguments as `cohere_tng.Transport` (see [TNG configuration docs](https://github.com/cohere-ai/tng/blob/cohere/docs/configuration.md)
for the full schema). The only difference is that `conseel` provides sensible
defaults:

- **`verify`** — Defaults to Intel Trust Authority attestation. Pass `None` to
  disable verification (not recommended for production).
- **`ohttp`** — Defaults include forwarding `authorization` headers and
  promoting the `model` JSON body field to `x-gateway-model-name` via
  `body_field_headers`.
