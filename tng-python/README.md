# tng

Python SDK for TNG — drop-in OHTTP encryption for `httpx` with TEE attestation
verification. Built as a native Rust extension via PyO3.

## Install

```bash
pip install tng
```

## Usage

### Sync

```python
import httpx
import tng

transport = tng.Transport(verify={
    "model": "passport",
    "as_provider": "ita",
    "ita_jwks_addr": "https://portal.trustauthority.intel.com",
    "policy_ids": ["my-policy"],
})

with httpx.Client(transport=transport) as client:
    resp = client.get("https://api.example.com/v1/chat")
    print(resp.json())

    # Attestation token is available as a response header
    token = resp.headers.get("x-tng-attestation-token")
```

### Async

```python
import httpx
import tng

transport = tng.AsyncTransport(verify={
    "model": "passport",
    "as_provider": "ita",
    "ita_jwks_addr": "https://portal.trustauthority.intel.com",
    "policy_ids": ["my-policy"],
})

async with httpx.AsyncClient(transport=transport) as client:
    resp = await client.get("https://api.example.com/v1/chat")
    print(resp.json())
```

### Response streaming

```python
with httpx.Client(transport=transport) as client:
    with client.stream("POST", url, json=payload) as resp:
        for chunk in resp.iter_bytes():
            process(chunk)
```

### Request streaming

Request bodies provided as generators are streamed through OHTTP without
buffering the entire payload in memory:

```python
def audio_chunks():
    with open("recording.wav", "rb") as f:
        while chunk := f.read(8192):
            yield chunk

with httpx.Client(transport=transport) as client:
    resp = client.post(url, content=audio_chunks())
```

## Configuration

Both `verify` and `ohttp` follow the same schema as TNG's
[configuration](../docs/configuration.md).

- **`verify`** (required) — Attestation verification config dict. Pass `None`
  to explicitly disable verification — not recommended for production.
- **`ohttp`** (optional) — OHTTP config dict (`forward_headers`,
  `tls_ca_certs`, etc.).

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install maturin httpx
.venv/bin/maturin develop
.venv/bin/pytest tests/
```

## How it works

The `tng` package embeds TNG's Rust OHTTP implementation directly into the
Python process via PyO3. When you make a request through `tng.Transport`:

1. The TEE running the TNG egress is verified via remote attestation (e.g.
   Intel Trust Authority) before any data is sent.
2. The request is encrypted using OHTTP (Oblivious HTTP) in-process.
3. The encrypted payload is sent to the TNG egress inside the verified TEE.
4. The egress decrypts and forwards the request to the actual backend.
5. The response follows the reverse path, decrypted in-process before being
   returned to `httpx`. The attestation token is included as an
   `x-tng-attestation-token` response header.

Both request and response bodies are streamed — large payloads are never fully
buffered in memory.
