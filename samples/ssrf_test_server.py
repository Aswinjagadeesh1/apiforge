"""Deliberately vulnerable SSRF test API — validates the SSRF check end to end.

Run with:  python -m samples.ssrf_test_server      (serves on http://localhost:8901)

Three endpoints, each taking a 'target_url' field, exercising all cases:

  POST /api/fetch/inband   -> IN-BAND SSRF: server fetches target_url and returns
                              the fetched body in the response. If target_url is
                              the metadata endpoint, metadata content comes back.

  POST /api/fetch/blind    -> BLIND SSRF: server fetches target_url server-side
                              but returns only {"status":"ok"} — the fetched
                              content never reaches the client. Detectable only
                              via an out-of-band callback.

  POST /api/fetch/safe     -> NOT VULNERABLE: server stores target_url and echoes
                              it back WITHOUT fetching it. The SSRF check must NOT
                              flag this (false-positive guard test).

A tiny built-in "metadata" endpoint at /latest/meta-data/ lets the in-band case
work fully offline (no real cloud needed): point target_url at
http://127.0.0.1:8901/latest/meta-data/ and you get realistic metadata content.
Uses only the standard library.
"""
from __future__ import annotations

import json
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8901

FAKE_METADATA = (
    "ami-id\nami-launch-index\nhostname\niam/\ninstance-id\n"
    "local-ipv4\npublic-keys/\nsecurity-credentials/\nreservation-id\n"
)


def _server_side_fetch(url: str, timeout: float = 3.0) -> str:
    """The vulnerable behaviour: the server fetches a user-supplied URL."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vuln-app"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(4096).decode("utf-8", "replace")
    except Exception as exc:
        return f"fetch-error: {exc}"


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode())

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def do_GET(self):
        # Built-in fake cloud metadata so the in-band case works offline.
        if self.path.startswith("/latest/meta-data"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(FAKE_METADATA.encode())
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        body = self._body()
        url = body.get("target_url", "")

        if self.path == "/api/fetch/inband":
            # VULNERABLE (in-band): fetch and return the content.
            fetched = _server_side_fetch(url) if url else ""
            self._json(200, {"status": "ok", "fetched_content": fetched})

        elif self.path == "/api/fetch/blind":
            # VULNERABLE (blind): fetch server-side, reveal nothing.
            if url:
                _server_side_fetch(url)
            self._json(200, {"status": "ok"})  # content NOT returned

        elif self.path == "/api/fetch/safe":
            # NOT VULNERABLE: store & echo, never fetch.
            self._json(200, {"status": "ok", "saved_url": url})

        else:
            self._json(404, {"error": "not found"})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"SSRF test server on http://localhost:{PORT}")
    print("  POST /api/fetch/inband  (in-band SSRF)")
    print("  POST /api/fetch/blind   (blind SSRF)")
    print("  POST /api/fetch/safe    (NOT vulnerable — must not flag)")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
