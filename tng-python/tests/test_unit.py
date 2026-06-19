"""Unit tests for the tng Python SDK (no network required)."""

import pytest

from tng.transport import Transport, AsyncTransport, _build_config


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
