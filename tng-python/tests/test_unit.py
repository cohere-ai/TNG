"""Unit tests for the tng Python SDK (no network required)."""

import pytest

import tng
from tng._native import TngClient, TngResponse, RequestSender
from tng.transport import Transport, AsyncTransport, _build_config


class TestImports:
    def test_top_level_exports(self):
        assert hasattr(tng, "Transport")
        assert hasattr(tng, "AsyncTransport")

    def test_native_classes_available(self):
        assert TngClient is not None
        assert TngResponse is not None
        assert RequestSender is not None


class TestBuildConfig:
    def test_verify_none_sets_no_ra(self):
        cfg = _build_config(verify=None, ohttp=None, forward_headers=None)
        assert cfg["no_ra"] is True
        assert "verify" not in cfg

    def test_verify_dict_passed_through(self):
        v = {"as_provider": "ita", "as_addr": "https://example.com"}
        cfg = _build_config(verify=v, ohttp=None, forward_headers=None)
        assert cfg["verify"] == v
        assert "no_ra" not in cfg

    def test_ohttp_forwarded(self):
        ohttp = {"tls_ca_certs": "/path/to/cert"}
        cfg = _build_config(verify=None, ohttp=ohttp, forward_headers=None)
        assert cfg["ohttp"]["tls_ca_certs"] == "/path/to/cert"

    def test_ohttp_not_mutated(self):
        ohttp = {"key": "val"}
        _build_config(verify=None, ohttp=ohttp, forward_headers=["x-foo"])
        assert "forward_headers" not in ohttp

    def test_forward_headers_added_to_ohttp(self):
        cfg = _build_config(verify=None, ohttp=None, forward_headers=["authorization"])
        assert cfg["ohttp"]["forward_headers"] == ["authorization"]

    def test_forward_headers_merged_with_ohttp(self):
        ohttp = {"tls_ca_certs": "/cert"}
        cfg = _build_config(
            verify=None, ohttp=ohttp, forward_headers=["x-key"]
        )
        assert cfg["ohttp"]["tls_ca_certs"] == "/cert"
        assert cfg["ohttp"]["forward_headers"] == ["x-key"]

    def test_empty_forward_headers_not_set(self):
        cfg = _build_config(verify=None, ohttp=None, forward_headers=[])
        assert "forward_headers" not in cfg.get("ohttp", {})

    def test_no_ohttp_no_headers(self):
        cfg = _build_config(verify=None, ohttp=None, forward_headers=None)
        assert cfg["ohttp"] == {}


class TestTransportInit:
    def test_default_verify_requires_api_key(self):
        with pytest.raises(RuntimeError, match="api_key"):
            Transport()

    def test_verify_none(self):
        t = Transport(verify=None)
        assert t._client is not None

    def test_verify_ita_requires_api_key(self):
        with pytest.raises(RuntimeError, match="api_key"):
            Transport(verify={"as_provider": "ita"})

    def test_forward_headers(self):
        t = Transport(verify=None, forward_headers=["authorization", "x-key"])
        assert t._client is not None

    def test_attach_attestation_header(self):
        t = Transport(verify=None, attach_attestation_header=True)
        assert t._attach_attestation_header is True

    def test_attestation_token_none_initially(self):
        t = Transport(verify=None)
        assert t.attestation_token is None

    def test_context_manager(self):
        with Transport(verify=None) as t:
            assert t._client is not None


class TestAsyncTransportInit:
    def test_default_verify_requires_api_key(self):
        with pytest.raises(RuntimeError, match="api_key"):
            AsyncTransport()

    def test_verify_none(self):
        t = AsyncTransport(verify=None)
        assert t._client is not None

    def test_verify_ita_requires_api_key(self):
        with pytest.raises(RuntimeError, match="api_key"):
            AsyncTransport(verify={"as_provider": "ita"})

    def test_forward_headers(self):
        t = AsyncTransport(verify=None, forward_headers=["authorization"])
        assert t._client is not None

    def test_attach_attestation_header(self):
        t = AsyncTransport(verify=None, attach_attestation_header=True)
        assert t._attach_attestation_header is True

    def test_attestation_token_none_initially(self):
        t = AsyncTransport(verify=None)
        assert t.attestation_token is None


class TestTngClientDirect:
    """Test TngClient construction directly via the Rust binding."""

    def test_create_no_ra(self):
        c = TngClient({"no_ra": True, "ohttp": {}})
        assert c is not None

    def test_create_with_verify_requires_api_key(self):
        with pytest.raises(RuntimeError, match="api_key"):
            TngClient({"verify": {"as_provider": "ita"}, "ohttp": {}})
