"""httpx Transport implementations that route through an in-process TNG ingress."""

from __future__ import annotations

from typing import Any, Optional

import httpx

from tng._native import TngInstance


class Transport(httpx.BaseTransport):
    """An httpx Transport that routes all requests through an in-process TNG ingress.

    TNG encrypts the traffic via OHTTP before it leaves the machine.
    The destination is determined dynamically from each request's Host header,
    so a single Transport can talk to multiple TNG-protected backends.

    By default, ITA attestation verification is enabled — the remote TEE is
    verified before any data is sent. Set $ITA_API_KEY in your environment.

    Usage with OpenAI:
        transport = tng.Transport()
        client = OpenAI(
            base_url="https://model-vault.example.com/v1",
            http_client=httpx.Client(transport=transport),
        )

    Usage with Cohere:
        transport = tng.Transport()
        co = cohere.ClientV2(
            base_url="https://model-vault.example.com",
            httpx_client=httpx.Client(transport=transport),
        )

    Custom verification config:
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
        dst_filters: Optional[list[str]] = None,
        attach_attestation_header: bool = False,
        _raw_config: Optional[dict] = None,
    ):
        """Create a TNG Transport.

        Args:
            verify: Attestation verification config dict, passed directly to TNG.
                    Defaults to ITA verification ({"as_provider": "ita"}).
                    Set to None to disable verification (testing only).
                    Common fields:
                      - as_provider: "ita" or "coco" (default: "ita")
                      - model: "background_check" or "passport" (default: "background_check")
                      - as_addr: Attestation service URL
                      - api_key: ITA API key (or set $ITA_API_KEY env var)
                      - policy_ids: list of policy IDs to enforce
            dst_filters: Optional allowlist of destination patterns
                         (e.g. ["*.example.com:443", "model-vault.internal:*"]).
                         If not set, all destinations are allowed.
            attach_attestation_header: Inject X-TNG-Attestation-Token on responses
            _raw_config: Advanced — pass a raw AddIngressArgs dict directly,
                         bypassing all other parameters.
        """
        if _raw_config is not None:
            ingress_config = _raw_config
        else:
            ingress_config = _build_proxy_config(
                verify=verify,
                dst_filters=dst_filters,
            )

        self._instance = TngInstance(ingress_config)
        self._attach_attestation_header = attach_attestation_header
        self._inner_transport = httpx.HTTPTransport()
        self._port = self._instance.port()
        self._last_attestation_token: Optional[str] = None

    @property
    def port(self) -> int:
        """The localhost port the TNG ingress is listening on."""
        return self._port

    @property
    def attestation_token(self) -> Optional[str]:
        """The last attestation token (ITA JWT) received from the TNG egress.

        This is populated after the first successful request when `verify` is configured.
        Returns None if attestation is disabled or no request has been made yet.
        """
        return self._last_attestation_token

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Route the request through the in-process TNG ingress."""
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

        token = response.headers.get("x-tng-attestation-token")
        if token:
            self._last_attestation_token = token
            if not self._attach_attestation_header:
                del response.headers["x-tng-attestation-token"]

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
    """Async version of tng.Transport."""

    _DEFAULT_VERIFY: dict = {"as_provider": "ita"}

    def __init__(
        self,
        *,
        verify: Optional[dict] = _DEFAULT_VERIFY,
        dst_filters: Optional[list[str]] = None,
        attach_attestation_header: bool = False,
        _raw_config: Optional[dict] = None,
    ):
        if _raw_config is not None:
            ingress_config = _raw_config
        else:
            ingress_config = _build_proxy_config(
                verify=verify,
                dst_filters=dst_filters,
            )

        self._instance = TngInstance(ingress_config)
        self._attach_attestation_header = attach_attestation_header
        self._inner_transport = httpx.AsyncHTTPTransport()
        self._port = self._instance.port()
        self._last_attestation_token: Optional[str] = None

    @property
    def port(self) -> int:
        return self._port

    @property
    def attestation_token(self) -> Optional[str]:
        """The last attestation token (ITA JWT) received from the TNG egress."""
        return self._last_attestation_token

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

        token = response.headers.get("x-tng-attestation-token")
        if token:
            self._last_attestation_token = token
            if not self._attach_attestation_header:
                del response.headers["x-tng-attestation-token"]

        return response

    async def aclose(self) -> None:
        await self._inner_transport.aclose()
        self._instance.close()

    async def __aenter__(self) -> "AsyncTransport":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()


def _build_proxy_config(
    *,
    verify: Optional[dict],
    dst_filters: Optional[list[str]],
) -> dict:
    """Build an AddIngressArgs dict using http_proxy mode."""
    http_proxy_config: dict[str, Any] = {
        "proxy_listen": {"host": "127.0.0.1", "port": 0},
    }
    if dst_filters:
        http_proxy_config["dst_filters"] = dst_filters

    config: dict[str, Any] = {
        "http_proxy": http_proxy_config,
        "ohttp": {},
    }

    if verify is not None:
        config["verify"] = verify
    else:
        config["no_ra"] = True

    return config
