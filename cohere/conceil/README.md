# conceil

Drop-in encrypted transport for AI SDKs. Wraps [tng](../../tng-python) to route
requests through OHTTP encryption with TEE attestation verification, and
automatically promotes the `model` field from JSON request bodies into an
`x-gateway-model-name` header for backend routing.

## Install

```bash
pip install conceil
```

`conceil` depends on the `tng` package (installed automatically).

## Usage

### Cohere

```python
import cohere
import httpx
from conceil import Transport

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
from conceil import Transport

client = OpenAI(
    http_client=httpx.Client(transport=Transport()),
)
client.chat.completions.create(model="gpt-4", messages=[...])
```

### Async

```python
import httpx
from conceil import AsyncTransport

async with httpx.AsyncClient(transport=AsyncTransport()) as client:
    resp = await client.post(url, json={"model": "command-a-plus-05-2026", ...})
```

## What it does

1. **Encrypts** all traffic via OHTTP so that even the network infrastructure
   cannot inspect request or response payloads.
2. **Verifies** the remote TEE via Intel Trust Authority attestation before
   sending any data (configurable via the `verify` parameter).
3. **Extracts** the `model` field from JSON request bodies and sets it as the
   `x-gateway-model-name` HTTP header for gateway routing. Non-JSON requests
   (e.g. multipart audio uploads) are streamed through without inspection.
4. **Forwards** `authorization` and `x-gateway-model-name` headers through the
   OHTTP layer to the backend.

## Configuration

`Transport` and `AsyncTransport` accept the same `verify` and `ohttp` keyword
arguments as `tng.Transport` (see [TNG configuration docs](../../docs/configuration.md)
for the full schema). The only difference is that `conceil` provides sensible
defaults:

- **`verify`** — Defaults to Intel Trust Authority attestation. Pass `None` to
  disable verification (not recommended for production).
- **`ohttp`** — Defaults include forwarding `authorization` and
  `x-gateway-model-name` headers.
