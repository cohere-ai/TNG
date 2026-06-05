"""Integration tests for tng.Transport.

These tests require a TNG egress running on localhost:18080 with OHTTP
self_generated keys and no_ra, plus an HTTP backend on localhost:9999.

Start them with:
    docker run -d --name tng-backend-test --network host python:3.12-slim \
      python3 -c "
    from http.server import HTTPServer, BaseHTTPRequestHandler
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Hello from backend!')
        def do_POST(self):
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a): pass
    HTTPServer(('0.0.0.0', 9999), H).serve_forever()
    "

    docker run -d --name tng-egress-test --network host \
      -v /tmp/tng-egress-test.json:/etc/tng/conf.json:ro \
      ghcr.io/cohere-ai/tng:latest \
      tng launch --config-file /etc/tng/conf.json
"""

import httpx
import pytest

import tng


EGRESS_URL = "http://127.0.0.1:18080"


@pytest.fixture
def transport():
    t = tng.Transport(no_ra=True)
    yield t
    t.close()


def test_get_request(transport):
    with httpx.Client(transport=transport) as client:
        resp = client.get(f"{EGRESS_URL}/")
        assert resp.status_code == 200
        assert resp.text == "Hello from backend!"


def test_post_request(transport):
    with httpx.Client(transport=transport) as client:
        resp = client.post(f"{EGRESS_URL}/api", json={"hello": "world"})
        assert resp.status_code == 200
        assert resp.json() is not None


def test_multiple_requests(transport):
    with httpx.Client(transport=transport) as client:
        for _ in range(5):
            resp = client.get(f"{EGRESS_URL}/")
            assert resp.status_code == 200


def test_streaming(transport):
    with httpx.Client(transport=transport) as client:
        with client.stream("GET", f"{EGRESS_URL}/") as resp:
            assert resp.status_code == 200
            body = b"".join(resp.iter_bytes())
            assert body == b"Hello from backend!"


def test_transport_port(transport):
    assert transport.port > 0
    assert transport.port < 65536
