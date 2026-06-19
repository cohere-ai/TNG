"""httpx Transport implementations backed by a direct PyO3 binding to TNG's OHTTP layer."""

from __future__ import annotations

from typing import Any, AsyncIterator, Iterator, Optional, Tuple

import httpx

from tng._native import TngClient, TngResponse, TngTimeoutError

_ATTESTATION_HEADER = "x-tng-attestation-token"


def _extract_timeouts(request: httpx.Request) -> Tuple[Optional[float], Optional[float]]:
    """Return (write_timeout, read_timeout) from the per-request extensions.

    httpx populates ``request.extensions["timeout"]`` with a dict mapping
    ``{"connect": ..., "read": ..., "write": ..., "pool": ...}`` where each
    value is either a float (seconds) or None.
    """
    timeout = request.extensions.get("timeout")
    if timeout is None:
        return None, None
    if isinstance(timeout, dict):
        return timeout.get("write"), timeout.get("read")
    # httpx.Timeout object (has .write / .read attributes)
    return getattr(timeout, "write", None), getattr(timeout, "read", None)


def _build_config(
    verify: Optional[dict],
    ohttp: Optional[dict],
) -> dict:
    """Build a CommonArgs-shaped config dict for the Rust layer."""
    config: dict[str, Any] = {
        "ohttp": dict(ohttp) if ohttp else {},
    }
    if verify is not None:
        config["verify"] = verify
    else:
        config["no_ra"] = True
    return config


def _build_response_headers(tng_response: TngResponse) -> dict[str, str]:
    headers = dict(tng_response.headers)
    if tng_response.attestation_token is not None:
        headers[_ATTESTATION_HEADER] = tng_response.attestation_token
    return headers


class Transport(httpx.BaseTransport):
    """An httpx Transport that encrypts requests via TNG's OHTTP layer.

    The remote TEE is verified via attestation before any data is sent.
    When attestation is configured, each response includes an
    ``x-tng-attestation-token`` header with the verification token (JWT).

    Args:
        verify: Attestation verification config (required). Pass a dict
                to configure verification. To disable verification, pass
                ``None`` explicitly — not recommended for production.
        ohttp: OHTTP config dict (forward_headers, tls_ca_certs, etc.).
    """

    def __init__(
        self,
        *,
        verify: Optional[dict],
        ohttp: Optional[dict] = None,
    ):
        self._client = TngClient(_build_config(verify=verify, ohttp=ohttp))

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        write_timeout, read_timeout = _extract_timeouts(request)

        sender = self._client.start_request(
            str(request.method),
            str(request.url),
            request.headers.multi_items(),
        )
        try:
            for chunk in request.stream:
                sender.write(chunk, timeout_secs=write_timeout)
            tng_response = sender.finish(timeout_secs=read_timeout)
        except TngTimeoutError as exc:
            raise httpx.ReadTimeout(str(exc)) from exc

        return httpx.Response(
            status_code=tng_response.status,
            headers=_build_response_headers(tng_response),
            stream=_ResponseStream(tng_response),
        )

    def close(self) -> None:
        pass

    def __enter__(self) -> "Transport":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class AsyncTransport(httpx.AsyncBaseTransport):
    """Async version of :class:`Transport`."""

    def __init__(
        self,
        *,
        verify: Optional[dict],
        ohttp: Optional[dict] = None,
    ):
        self._client = TngClient(_build_config(verify=verify, ohttp=ohttp))

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        write_timeout, read_timeout = _extract_timeouts(request)

        sender = self._client.start_request(
            str(request.method),
            str(request.url),
            request.headers.multi_items(),
        )
        try:
            async for chunk in request.stream:
                await sender.write_async(chunk, timeout_secs=write_timeout)
            tng_response = await sender.finish_async(timeout_secs=read_timeout)
        except TngTimeoutError as exc:
            raise httpx.ReadTimeout(str(exc)) from exc

        return httpx.Response(
            status_code=tng_response.status,
            headers=_build_response_headers(tng_response),
            stream=_AsyncResponseStream(tng_response),
        )

    async def aclose(self) -> None:
        pass

    async def __aenter__(self) -> "AsyncTransport":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()


class _ResponseStream(httpx.SyncByteStream):
    """Wraps TngResponse iteration into an httpx SyncByteStream."""

    def __init__(self, tng_response: TngResponse) -> None:
        self._response = tng_response

    def __iter__(self) -> Iterator[bytes]:
        for chunk in self._response:
            yield bytes(chunk)

    def close(self) -> None:
        pass


class _AsyncResponseStream(httpx.AsyncByteStream):
    """Wraps TngResponse async iteration into an httpx AsyncByteStream."""

    def __init__(self, tng_response: TngResponse) -> None:
        self._response = tng_response

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._response:
            yield bytes(chunk)

    async def aclose(self) -> None:
        pass
