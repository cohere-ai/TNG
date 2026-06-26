"""Unit tests for the tng Python SDK (no network required)."""

import socketserver
import threading
import time

import httpx
import pytest

from tng.transport import Transport, AsyncTransport, _build_config, _extract_timeouts


class TestBuildConfig:
    def test_verify_none_sets_no_ra(self):
        cfg = _build_config(verify=None, ohttp=None)
        assert cfg["no_ra"] is True
        assert "verify" not in cfg

    def test_verify_dict_passed_through(self):
        v = {"as_provider": "ita", "as_addr": "https://example.com"}
        cfg = _build_config(verify=v, ohttp=None)
        assert cfg["verify"] is v
        assert "no_ra" not in cfg

    def test_ohttp_defaults_to_empty(self):
        cfg = _build_config(verify=None, ohttp=None)
        assert cfg["ohttp"] == {}

    def test_ohttp_forwarded(self):
        ohttp = {"tls_ca_certs": "/path/to/cert"}
        cfg = _build_config(verify=None, ohttp=ohttp)
        assert cfg["ohttp"] == ohttp


class TestExtractTimeouts:
    def test_no_timeout_returns_none(self):
        request = httpx.Request("GET", "http://example.com")
        request.extensions = {}
        assert _extract_timeouts(request) == (None, None)

    def test_dict_timeout_extracts_values(self):
        request = httpx.Request("GET", "http://example.com")
        request.extensions = {
            "timeout": {"connect": 1.0, "read": 5.0, "write": 3.0, "pool": 2.0}
        }
        write_t, read_t = _extract_timeouts(request)
        assert write_t == 3.0
        assert read_t == 5.0


class TestTimeoutBehavior:
    def test_sync_transport_raises_on_timeout(self):
        """A stalling server must trigger httpx.TimeoutException within the deadline."""
        stop = threading.Event()

        class _SilentHandler(socketserver.BaseRequestHandler):
            def handle(self):
                stop.wait(timeout=10)

        with socketserver.TCPServer(("127.0.0.1", 0), _SilentHandler) as srv:
            port = srv.server_address[1]
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                with httpx.Client(transport=Transport(verify=None)) as client:
                    start = time.monotonic()
                    with pytest.raises(httpx.TimeoutException):
                        client.get(f"http://127.0.0.1:{port}/test", timeout=0.5)
                    assert time.monotonic() - start < 3.0
            finally:
                stop.set()
                srv.shutdown()

    def test_stream_timeout_raises_read_timeout(self):
        """A mid-body stall must surface as httpx.ReadTimeout, not block forever."""
        from tng._native import TngTimeoutError
        from tng.transport import _ResponseStream

        class _StallingResponse:
            """Yields one chunk then simulates a body-stream timeout."""
            def set_read_timeout(self, _t):
                pass
            def close(self):
                pass
            def __iter__(self):
                yield b"partial"
                raise TngTimeoutError("timed out reading response body")

        stream = _ResponseStream(_StallingResponse(), read_timeout=1.0)
        chunks = []
        with pytest.raises(httpx.ReadTimeout):
            for chunk in stream:
                chunks.append(chunk)
        assert chunks == [b"partial"]


class TestTransportInit:
    def test_requires_verify(self):
        with pytest.raises(TypeError):
            Transport()

    def test_verify_none_creates_client(self):
        t = Transport(verify=None)
        assert t._client is not None

    def test_invalid_verify_raises(self):
        with pytest.raises(RuntimeError):
            Transport(verify={"as_provider": "ita"})

    def test_accepts_ohttp(self):
        t = Transport(verify=None, ohttp={"forward_headers": ["authorization"]})
        assert t._client is not None

    def test_context_manager(self):
        with Transport(verify=None) as t:
            assert t._client is not None


class TestAsyncTransportInit:
    def test_requires_verify(self):
        with pytest.raises(TypeError):
            AsyncTransport()

    def test_verify_none_creates_client(self):
        t = AsyncTransport(verify=None)
        assert t._client is not None

    def test_invalid_verify_raises(self):
        with pytest.raises(RuntimeError):
            AsyncTransport(verify={"as_provider": "ita"})
