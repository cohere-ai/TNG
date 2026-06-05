"""TNG Python SDK — Transparent OHTTP encryption for confidential AI.

Provides drop-in httpx Transport replacements that route traffic through
an in-process TNG ingress for end-to-end encryption via OHTTP.

Usage:
    import tng
    import httpx

    transport = tng.Transport(no_ra=True)  # or omit no_ra for production
    client = httpx.Client(transport=transport)
    resp = client.get("https://model-vault.example.com/v1/models")
"""

from tng._native import TngInstance
from tng.transport import Transport, AsyncTransport

__all__ = ["Transport", "AsyncTransport", "TngInstance"]
