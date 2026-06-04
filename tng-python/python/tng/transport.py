"""httpx Transport implementations that route through an in-process TNG ingress."""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from tng._native import TngInstance


class Transport(httpx.BaseTransport):
    """An httpx Transport that routes all requests through an in-process TNG ingress.

    TNG encrypts the traffic via OHTTP before it leaves the machine.

    Usage with OpenAI:
        transport = Transport.connect("https://model-vault.example.com")
        client = OpenAI(
            base_url="https://model-vault.example.com/v1",
            http_client=httpx.Client(transport=transport),
        )

    Usage with Cohere:
        transport = Transport.connect("https://model-vault.example.com")
        co = cohere.ClientV2(
            base_url="https://model-vault.example.com",
            httpx_client=httpx.Client(transport=transport),
        )
    """

    def __init__(
        self,
        *,
        mapping: Optional[dict] = None,
        http_proxy: Optional[dict] = None,
        socks5: Optional[dict] = None,
        ohttp: Optional[dict] = None,
        verify: Optional[dict] = None,
        attest: Optional[dict] = None,
        no_ra: bool = False,
        attach_attestation_header: bool = False,
    ):
        """Create a Transport from explicit AddIngressArgs fields.

        Exactly one of mapping, http_proxy, or socks5 must be provided.
        """
        ingress_config = _build_ingress_config(
            mapping=mapping,
            http_proxy=http_proxy,
            socks5=socks5,
            ohttp=ohttp,
            verify=verify,
            attest=attest,
            no_ra=no_ra,
        )
        self._instance = TngInstance(ingress_config)
        self._attach_attestation_header = attach_attestation_header
        self._inner_transport = httpx.HTTPTransport()
        self._port = self._instance.port()

    @classmethod
    def connect(
        cls,
        target: str,
        *,
        as_provider: str = "ita",
        as_addr: Optional[str] = None,
        attach_attestation_header: bool = False,
        no_ra: bool = False,
    ) -> "Transport":
        """Create a Transport with simplified configuration.

        Args:
            target: The target URL (e.g. "https://model-vault.example.com")
            as_provider: Attestation service provider ("ita" or "coco")
            as_addr: Attestation service URL (optional, uses provider default)
            attach_attestation_header: Inject X-TNG-Attestation-Token on responses
            no_ra: Disable remote attestation (for testing only)
        """
        parsed = urlparse(target)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        mapping = {
            "in": {"host": "127.0.0.1", "port": 0},
            "out": {"host": host, "port": port},
        }

        verify: Optional[dict[str, Any]] = None
        if not no_ra:
            verify = {"as_provider": as_provider}
            if as_addr:
                verify["as_addr"] = as_addr

        return cls(
            mapping=mapping,
            ohttp={},
            verify=verify,
            no_ra=no_ra,
            attach_attestation_header=attach_attestation_header,
        )

    @property
    def port(self) -> int:
        """The localhost port the TNG ingress is listening on."""
        return self._port

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Route the request through the in-process TNG ingress."""
        # Rewrite the URL to point at the local TNG ingress
        local_url = request.url.copy_with(
            scheme="http",
            host="127.0.0.1",
            port=self._port,
        )
        proxied_request = httpx.Request(
            method=request.method,
            url=local_url,
            headers=request.headers,
            content=request.content,
            extensions=request.extensions,
        )

        response = self._inner_transport.handle_request(proxied_request)
        return response

    def close(self) -> None:
        """Gracefully shut down the TNG ingress."""
        self._inner_transport.close()
        self._instance.close()

    def __enter__(self) -> "Transport":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class AsyncTransport(httpx.AsyncBaseTransport):
    """An async httpx Transport that routes requests through an in-process TNG ingress."""

    def __init__(
        self,
        *,
        mapping: Optional[dict] = None,
        http_proxy: Optional[dict] = None,
        socks5: Optional[dict] = None,
        ohttp: Optional[dict] = None,
        verify: Optional[dict] = None,
        attest: Optional[dict] = None,
        no_ra: bool = False,
        attach_attestation_header: bool = False,
    ):
        ingress_config = _build_ingress_config(
            mapping=mapping,
            http_proxy=http_proxy,
            socks5=socks5,
            ohttp=ohttp,
            verify=verify,
            attest=attest,
            no_ra=no_ra,
        )
        self._instance = TngInstance(ingress_config)
        self._attach_attestation_header = attach_attestation_header
        self._inner_transport = httpx.AsyncHTTPTransport()
        self._port = self._instance.port()

    @classmethod
    def connect(
        cls,
        target: str,
        *,
        as_provider: str = "ita",
        as_addr: Optional[str] = None,
        attach_attestation_header: bool = False,
        no_ra: bool = False,
    ) -> "AsyncTransport":
        parsed = urlparse(target)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        mapping = {
            "in": {"host": "127.0.0.1", "port": 0},
            "out": {"host": host, "port": port},
        }

        verify: Optional[dict[str, Any]] = None
        if not no_ra:
            verify = {"as_provider": as_provider}
            if as_addr:
                verify["as_addr"] = as_addr

        return cls(
            mapping=mapping,
            ohttp={},
            verify=verify,
            no_ra=no_ra,
            attach_attestation_header=attach_attestation_header,
        )

    @property
    def port(self) -> int:
        return self._port

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        local_url = request.url.copy_with(
            scheme="http",
            host="127.0.0.1",
            port=self._port,
        )
        proxied_request = httpx.Request(
            method=request.method,
            url=local_url,
            headers=request.headers,
            content=request.content,
            extensions=request.extensions,
        )

        response = await self._inner_transport.handle_async_request(proxied_request)
        return response

    async def aclose(self) -> None:
        await self._inner_transport.aclose()
        self._instance.close()

    async def __aenter__(self) -> "AsyncTransport":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()


def _build_ingress_config(
    *,
    mapping: Optional[dict],
    http_proxy: Optional[dict],
    socks5: Optional[dict],
    ohttp: Optional[dict],
    verify: Optional[dict],
    attest: Optional[dict],
    no_ra: bool,
) -> dict:
    """Build an AddIngressArgs-compatible dict from the provided fields."""
    modes = [
        ("mapping", mapping),
        ("http_proxy", http_proxy),
        ("socks5", socks5),
    ]
    provided = [(name, val) for name, val in modes if val is not None]

    if len(provided) == 0:
        raise ValueError("Exactly one of mapping, http_proxy, or socks5 must be provided")
    if len(provided) > 1:
        raise ValueError(
            f"Only one ingress mode can be specified, got: {[n for n, _ in provided]}"
        )

    mode_name, mode_value = provided[0]
    config: dict[str, Any] = {mode_name: mode_value}

    if ohttp is not None:
        config["ohttp"] = ohttp

    if no_ra:
        config["no_ra"] = True
    if verify is not None:
        config["verify"] = verify
    if attest is not None:
        config["attest"] = attest

    return config
