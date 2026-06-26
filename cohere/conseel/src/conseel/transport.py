"""Encrypted httpx transports for AI APIs.

Extends tng.Transport with Cohere-specific defaults (ITA attestation,
header forwarding) and automatic model-name header promotion from JSON
request bodies.
"""

from __future__ import annotations

import copy
import json
from typing import Optional

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

_UNSET = object()


def _should_extract_model(request: httpx.Request) -> bool:
    if _MODEL_HEADER in request.headers:
        return False
    return "json" in request.headers.get("content-type", "")


def _promote_model_from_body(request: httpx.Request, body: bytes) -> None:
    if not body:
        return
    try:
        model = json.loads(body).get("model")
        if model:
            request.headers[_MODEL_HEADER] = str(model)
    except (json.JSONDecodeError, AttributeError):
        pass


class Transport(tng.Transport):
    def __init__(
        self,
        *,
        verify: Optional[dict] = _UNSET,
        ohttp: Optional[dict] = None,
    ):
        if verify is _UNSET:
            verify = copy.deepcopy(_DEFAULT_VERIFY)
        ohttp = dict(ohttp) if ohttp else {}
        ohttp.setdefault("forward_headers", list(_DEFAULT_FORWARD_HEADERS))
        super().__init__(verify=verify, ohttp=ohttp)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if _should_extract_model(request):
            _promote_model_from_body(request, request.read())
        return super().handle_request(request)


class AsyncTransport(tng.AsyncTransport):
    def __init__(
        self,
        *,
        verify: Optional[dict] = _UNSET,
        ohttp: Optional[dict] = None,
    ):
        if verify is _UNSET:
            verify = copy.deepcopy(_DEFAULT_VERIFY)
        ohttp = dict(ohttp) if ohttp else {}
        ohttp.setdefault("forward_headers", list(_DEFAULT_FORWARD_HEADERS))
        super().__init__(verify=verify, ohttp=ohttp)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if _should_extract_model(request):
            _promote_model_from_body(request, await request.aread())
        return await super().handle_async_request(request)
