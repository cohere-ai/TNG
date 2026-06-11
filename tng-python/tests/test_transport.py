"""Integration tests for tng.Transport and tng.AsyncTransport.

These tests require a TNG egress + backend. There are two ways to run them:

1. Via the Rust test harness (recommended):
     cargo test -p tng-testsuite --features python-sdk --test python_sdk

2. Manually with a pre-running egress:
     TNG_EGRESS_HOST=192.168.1.1 TNG_EGRESS_PORT=20001 \
       .venv/bin/pytest tests/test_transport.py -v
"""

import os

import httpx
import pytest

import tng

EGRESS_HOST = os.environ.get("TNG_EGRESS_HOST", "192.168.1.1")
EGRESS_PORT = os.environ.get("TNG_EGRESS_PORT", "20001")
EGRESS_BASE = f"http://{EGRESS_HOST}:{EGRESS_PORT}"


@pytest.fixture
def transport():
    t = tng.Transport(verify=None)
    yield t
    t.close()


@pytest.fixture
def async_transport():
    return tng.AsyncTransport(verify=None)


class TestSyncTransport:
    def test_get_request(self, transport):
        with httpx.Client(transport=transport) as client:
            resp = client.get(f"{EGRESS_BASE}/test?q=1")
            assert resp.status_code == 200
            assert resp.text == "Hello World HTTP!"

    def test_streaming(self, transport):
        with httpx.Client(transport=transport) as client:
            with client.stream("GET", f"{EGRESS_BASE}/test?q=1") as resp:
                assert resp.status_code == 200
                chunks = list(resp.iter_bytes())
                assert len(chunks) > 0
                assert b"".join(chunks) == b"Hello World HTTP!"

    def test_multiple_requests(self, transport):
        with httpx.Client(transport=transport) as client:
            for _ in range(3):
                resp = client.get(f"{EGRESS_BASE}/test?q=1")
                assert resp.status_code == 200


@pytest.mark.asyncio
class TestAsyncTransport:
    async def test_async_get(self, async_transport):
        async with httpx.AsyncClient(transport=async_transport) as client:
            resp = await client.get(f"{EGRESS_BASE}/test?q=1")
            assert resp.status_code == 200
            assert resp.text == "Hello World HTTP!"

    async def test_async_streaming(self, async_transport):
        async with httpx.AsyncClient(transport=async_transport) as client:
            async with client.stream("GET", f"{EGRESS_BASE}/test?q=1") as resp:
                assert resp.status_code == 200
                chunks = []
                async for chunk in resp.aiter_bytes():
                    chunks.append(chunk)
                assert len(chunks) > 0
                assert b"".join(chunks) == b"Hello World HTTP!"
