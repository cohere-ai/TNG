"""httpx Transport implementations backed by a direct PyO3 binding to TNG's OHTTP layer."""

from __future__ import annotations

from typing import Any, AsyncIterator, Iterator, Optional

import httpx

from tng._native import TngClient, TngResponse

_DEFAULT_VERIFY: dict = {"as_provider": "ita"}
_ATTESTATION_HEADER = "x-tng-attestation-token"


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

    Traffic goes directly through the in-process OHTTP security layer
    (no localhost proxy). The remote TEE is verified via attestation
    before any data is sent. When attestation is configured, each
    response includes an ``x-tng-attestation-token`` header with the
    verification token (JWT).

    Usage:
        with httpx.Client(transport=tng.Transport()) as client:
            resp = client.get("https://model-vault.example.com/v1/models")
            token = resp.headers.get("x-tng-attestation-token")

    Streaming:
        with httpx.Client(transport=tng.Transport()) as client:
            with client.stream("POST", url, json=payload) as resp:
                for chunk in resp.iter_bytes():
                    process(chunk)

    Custom verification:
        tng.Transport(verify={
            "as_provider": "ita",
            "as_addr": "https://api.trustauthority.intel.com",
            "policy_ids": ["my-policy"],
        })

    Skip verification (testing only):
        tng.Transport(verify=None)
    """

    def __init__(
        self,
        *,
        verify: Optional[dict] = _DEFAULT_VERIFY,
        ohttp: Optional[dict] = None,
    ):
        """Create a TNG Transport.

        Args:
            verify: Attestation verification config dict.
                    Defaults to ITA verification ({"as_provider": "ita"}).
                    Set to None to disable verification (testing only).
            ohttp: Raw OHTTP config dict (path_rewrites, tls_ca_certs,
                   forward_headers, etc.).
        """
        self._client = TngClient(_build_config(verify=verify, ohttp=ohttp))

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        sender = self._client.start_request(
            str(request.method),
            str(request.url),
            request.headers.multi_items(),
        )
        for chunk in request.stream:
            sender.write(chunk)
        tng_response = sender.finish()

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
    """Async version of tng.Transport.

    Usage:
        async with httpx.AsyncClient(transport=tng.AsyncTransport()) as client:
            async with client.stream("POST", url, json=payload) as resp:
                async for chunk in resp.aiter_bytes():
                    process(chunk)
    """

    def __init__(
        self,
        *,
        verify: Optional[dict] = _DEFAULT_VERIFY,
        ohttp: Optional[dict] = None,
    ):
        self._client = TngClient(_build_config(verify=verify, ohttp=ohttp))

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        sender = self._client.start_request(
            str(request.method),
            str(request.url),
            request.headers.multi_items(),
        )
        async for chunk in request.stream:
            await sender.write_async(chunk)
        tng_response = await sender.finish_async()

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
