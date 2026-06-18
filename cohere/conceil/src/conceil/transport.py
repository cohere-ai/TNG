"""Encrypted httpx transports for AI APIs.

Usage with Cohere:
    import cohere, httpx
    from conceil import Transport

    co = cohere.ClientV2(
        api_key="...",
        httpx_client=httpx.Client(transport=Transport()),
    )
    co.chat(model="command-a-plus-05-2026", messages=[...])

Usage with OpenAI:
    from openai import OpenAI
    from conceil import Transport

    client = OpenAI(
        http_client=httpx.Client(transport=Transport()),
    )
    client.chat.completions.create(model="gpt-4", messages=[...])
"""

from __future__ import annotations

import json
from typing import Any, Optional

import httpx

import tng

_MODEL_HEADER = "x-gateway-model-name"

_DEFAULT_FORWARD_HEADERS: list = ["authorization", _MODEL_HEADER]

_DEFAULT_VERIFY: dict = {
    "model": "passport",
    "as_provider": "ita",
    "ita_jwks_addr": "https://portal.trustauthority.intel.com",
    "policy_ids": ["cbeedffa-e224-4664-b6b4-573fcd4133d3"],
}


def _inject_model_header(request: httpx.Request) -> None:
    content_type = request.headers.get("content-type", "")
    if "json" not in content_type:
        return
    body = request.content
    if not body:
        return
    try:
        model = json.loads(body).get("model")
        if model:
            request.headers[_MODEL_HEADER] = model
    except (json.JSONDecodeError, AttributeError):
        pass


class Transport(httpx.BaseTransport):
    def __init__(
        self,
        *,
        verify: Optional[dict] = _DEFAULT_VERIFY,
        ohttp: Optional[dict] = None,
    ):
        ohttp = dict(ohttp) if ohttp else {}
        ohttp.setdefault("forward_headers", _DEFAULT_FORWARD_HEADERS)
        self._inner = tng.Transport(verify=verify, ohttp=ohttp)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        _inject_model_header(request)
        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()

    def __enter__(self) -> "Transport":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class AsyncTransport(httpx.AsyncBaseTransport):
    def __init__(
        self,
        *,
        verify: Optional[dict] = _DEFAULT_VERIFY,
        ohttp: Optional[dict] = None,
    ):
        ohttp = dict(ohttp) if ohttp else {}
        ohttp.setdefault("forward_headers", _DEFAULT_FORWARD_HEADERS)
        self._inner = tng.AsyncTransport(verify=verify, ohttp=ohttp)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        _inject_model_header(request)
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def __aenter__(self) -> "AsyncTransport":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()
