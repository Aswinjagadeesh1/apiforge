"""Deliberately vulnerable mock API — a tiny stand-in for crAPI/VAmPI.

Run with:  python -m samples.vuln_server
Serves on http://localhost:8899

Vulnerabilities intentionally present:
  * BOLA: /api/orders/{id} returns any order regardless of owner
  * BOLA: /api/profile/{id} returns any profile with the SAME body per user
  * BFLA: /api/admin/users reachable by any authenticated user
  * Mass assignment: PUT /api/profile/{id} accepts isAdmin/role and echoes them
  * Data exposure: profile responses include a password hash
Uses only the Python standard library (no external deps).
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKENS = {
    "token-user-a": "usera@test.com",
    "token-user-b": "userb@test.com",
}

# Fixed order/profile data. Note responses do NOT vary by user → BOLA.
ORDERS = {
    "1001": {"order_id": 1001, "item": "Laptop", "amount": 85000, "owner": "usera@test.com"},
    "1002": {"order_id": 1002, "item": "Phone", "amount": 55000, "owner": "userb@test.com"},
}
PROFILES = {
    "7": {
        "id": 7,
        "name": "Alice",
        "email": "usera@test.com",
        "password_hash": "$2b$10$abcdefghijklmnopqrstuv",
        "role": "user",
    }
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence default logging
        pass

    def _auth_ok(self):
        auth = self.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "").strip()
        return token in TOKENS

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, ValueError):
            return {}

    def do_POST(self):
        if self.path == "/identity/api/auth/login":
            data = self._read_body()
            email = data.get("email", "")
            # naive: hand out a fixed token per known user
            for tok, mail in TOKENS.items():
                if mail == email:
                    return self._send(200, {"token": tok})
            return self._send(401, {"error": "invalid credentials"})
        self._send(404, {"error": "not found"})

    def do_GET(self):
        if not self._auth_ok():
            return self._send(401, {"error": "unauthorized"})

        parts = self.path.strip("/").split("/")
        # /api/orders/{id}  → BOLA, no owner check
        if parts[:2] == ["api", "orders"] and len(parts) == 3:
            order = ORDERS.get(parts[2])
            return self._send(200, order) if order else self._send(404, {"error": "no order"})

        # /api/profile/{id} → BOLA + data exposure
        if parts[:2] == ["api", "profile"] and len(parts) == 3:
            profile = PROFILES.get(parts[2])
            return self._send(200, profile) if profile else self._send(404, {"error": "no profile"})

        # /api/admin/users → BFLA, any authed user allowed
        if parts == ["api", "admin", "users"]:
            return self._send(200, {"users": list(TOKENS.values())})

        self._send(404, {"error": "not found"})

    def do_PUT(self):
        if not self._auth_ok():
            return self._send(401, {"error": "unauthorized"})
        parts = self.path.strip("/").split("/")
        # PUT /api/profile/{id} → mass assignment, echoes whatever is sent
        if parts[:2] == ["api", "profile"] and len(parts) == 3:
            data = self._read_body()
            updated = dict(PROFILES.get(parts[2], {"id": int(parts[2])}))
            updated.update(data)  # blindly binds all fields → vuln
            return self._send(200, updated)
        self._send(404, {"error": "not found"})


def main(port: int = 8899):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Vulnerable mock API running on http://localhost:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
