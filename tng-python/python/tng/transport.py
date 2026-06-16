"""httpx Transport implementations backed by a direct PyO3 binding to TNG's OHTTP layer."""

from __future__ import annotations

from typing import Any, AsyncIterator, Iterator, Optional

import httpx

from tng._native import TngClient, TngResponse


def _build_config(
    verify: Optional[dict],
    ohttp: Optional[dict],
    forward_headers: Optional[list[str]],
) -> dict:
    """Build a CommonArgs-shaped config dict for the Rust layer."""
    ohttp_config = dict(ohttp) if ohttp else {}
    if forward_headers:
        ohttp_config["forward_headers"] = forward_headers

    config: dict[str, Any] = {
        "ohttp": ohttp_config,
    }
    if verify is not None:
        config["verify"] = verify
    else:
        config["no_ra"] = True
    return config


class Transport(httpx.BaseTransport):
    """An httpx Transport that encrypts requests via TNG's OHTTP layer.

    Traffic goes directly through the in-process OHTTP security layer
    (no localhost proxy). The remote TEE is verified via attestation
    before any data is sent.

    Usage with httpx:
        transport = tng.Transport()
        with httpx.Client(transport=transport) as client:
            resp = client.get("https://model-vault.example.com/v1/models")

    Streaming:
        with httpx.Client(transport=transport) as client:
            with client.stream("POST", url, json=payload) as resp:
                for chunk in resp.iter_bytes():
                    process(chunk)

    Custom verification:
        transport = tng.Transport(verify={
            "as_provider": "ita",
            "as_addr": "https://api.trustauthority.intel.com",
            "policy_ids": ["my-policy"],
        })

    Skip verification (testing only):
        transport = tng.Transport(verify=None)
    """

    _DEFAULT_VERIFY: dict = {"as_provider": "ita"}

    def __init__(
        self,
        *,
        verify: Optional[dict] = _DEFAULT_VERIFY,
        ohttp: Optional[dict] = None,
        forward_headers: Optional[list[str]] = None,
        attach_attestation_header: bool = False,
    ):
        """Create a TNG Transport.

        Args:
            verify: Attestation verification config dict.
                    Defaults to ITA verification ({"as_provider": "ita"}).
                    Set to None to disable verification (testing only).
            ohttp: Raw OHTTP config dict (path_rewrites, tls_ca_certs, etc.).
            forward_headers: Header names to forward to the TNG egress
                             (e.g. ["authorization", "x-routing-key"]).
            attach_attestation_header: Inject X-TNG-Attestation-Token on responses.
        """
        config = _build_config(
            verify=verify, ohttp=ohttp, forward_headers=forward_headers
        )
        self._client = TngClient(config)
        self._attach_attestation_header = attach_attestation_header
        self._last_attestation_token: Optional[str] = None

    @property
    def attestation_token(self) -> Optional[str]:
        """The last attestation token (JWT) received from the TNG egress.

        Populated after the first successful request when verification is
        configured. Returns None if attestation is disabled or no request
        has been made yet.
        """
        return self._last_attestation_token

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        headers_str = request.headers.multi_items()

        sender = self._client.start_request(
            str(request.method),
            str(request.url),
            headers_str,
        )
        for chunk in request.stream:
            sender.write(chunk)
        tng_response = sender.finish()

        if tng_response.attestation_token is not None:
            self._last_attestation_token = tng_response.attestation_token

        resp_headers = dict(tng_response.headers)
        if (
            self._attach_attestation_header
            and self._last_attestation_token is not None
        ):
            resp_headers["x-tng-attestation-token"] = self._last_attestation_token

        return httpx.Response(
            status_code=tng_response.status,
            headers=resp_headers,
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
        transport = tng.AsyncTransport()
        async with httpx.AsyncClient(transport=transport) as client:
            async with client.stream("POST", url, json=payload) as resp:
                async for chunk in resp.aiter_bytes():
                    process(chunk)
    """

    _DEFAULT_VERIFY: dict = {"as_provider": "ita"}

    def __init__(
        self,
        *,
        verify: Optional[dict] = _DEFAULT_VERIFY,
        ohttp: Optional[dict] = None,
        forward_headers: Optional[list[str]] = None,
        attach_attestation_header: bool = False,
    ):
        config = _build_config(
            verify=verify, ohttp=ohttp, forward_headers=forward_headers
        )
        self._client = TngClient(config)
        self._attach_attestation_header = attach_attestation_header
        self._last_attestation_token: Optional[str] = None

    @property
    def attestation_token(self) -> Optional[str]:
        """The last attestation token (JWT) received from the TNG egress."""
        return self._last_attestation_token

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        headers_str = request.headers.multi_items()

        sender = self._client.start_request(
            str(request.method),
            str(request.url),
            headers_str,
        )
        async for chunk in request.stream:
            await sender.write_async(chunk)
        tng_response = await sender.finish_async()

        if tng_response.attestation_token is not None:
            self._last_attestation_token = tng_response.attestation_token

        resp_headers = dict(tng_response.headers)
        if (
            self._attach_attestation_header
            and self._last_attestation_token is not None
        ):
            resp_headers["x-tng-attestation-token"] = self._last_attestation_token

        return httpx.Response(
            status_code=tng_response.status,
            headers=resp_headers,
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
