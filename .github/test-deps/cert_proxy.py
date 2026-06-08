#!/usr/bin/env python3
"""
Proxy that intercepts GET /certificate (returns a local PEM file) and
forwards all other requests to a real Attestation Service backend.

Usage:
    python3 cert_proxy.py [--cert /tmp/as-full.pem] [--listen 8080] [--backend http://127.0.0.1:8081]
"""
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
import urllib.error


def make_handler(cert_path: str, backend: str):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/certificate":
                with open(cert_path, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-pem-file")
                self.end_headers()
                self.wfile.write(data)
            else:
                self._proxy()

        def do_POST(self):
            self._proxy()

        def _proxy(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else None
            req = urllib.request.Request(
                backend + self.path, data=body, method=self.command
            )
            for k, v in self.headers.items():
                if k.lower() not in ("host", "content-length"):
                    req.add_header(k, v)
            try:
                resp = urllib.request.urlopen(req)
            except urllib.error.HTTPError as e:
                resp = e
            except Exception as e:
                self.send_response(502)
                self.end_headers()
                self.wfile.write(str(e).encode())
                return
            resp_body = resp.read()
            self.send_response(resp.status)
            for k, v in resp.headers.items():
                if k.lower() not in ("transfer-encoding",):
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp_body)

        def log_message(self, format, *args):
            print(f"[cert_proxy] {self.address_string()} {format % args}")

    return Handler


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", default="/tmp/as-full.pem", help="Path to PEM cert file")
    parser.add_argument("--listen", type=int, default=8080, help="Port to listen on")
    parser.add_argument("--backend", default="http://127.0.0.1:8081", help="AS backend URL")
    args = parser.parse_args()

    handler = make_handler(args.cert, args.backend)
    server = HTTPServer(("0.0.0.0", args.listen), handler)
    print(f"[cert_proxy] Listening on :{args.listen}, cert={args.cert}, backend={args.backend}")
    server.serve_forever()
