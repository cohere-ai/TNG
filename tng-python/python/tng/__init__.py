"""TNG Python SDK — Transparent OHTTP encryption for confidential AI.

Provides drop-in httpx Transport replacements that route traffic through
an in-process TNG ingress for end-to-end encryption via OHTTP.
"""

from tng._native import TngInstance
from tng.transport import Transport, AsyncTransport

__all__ = ["Transport", "AsyncTransport", "TngInstance"]
