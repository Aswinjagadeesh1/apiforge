"""Integration test: scan the mock vulnerable server end-to-end.

Starts the bundled vuln_server in a thread, authenticates two users, runs all
checks, and asserts the expected vulnerability classes are detected.
"""
import asyncio
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from apiforge.auth.jwt_auth import JWTAuthenticator
from apiforge.parser.postman import PostmanParser
from apiforge.scanner import Scanner
from samples.vuln_server import Handler

SAMPLES = Path(__file__).parent.parent / "samples"
PORT = 8901
BASE = f"http://localhost:{PORT}"


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)
    yield
    srv.shutdown()


@pytest.mark.asyncio
async def test_scan_detects_expected_vulns(server):
    parser = PostmanParser(SAMPLES / "vulnshop.postman.json")
    endpoints = parser.parse()

    auth = JWTAuthenticator(BASE, "/identity/api/auth/login", token_json_path="token")
    sessions = {
        "user_a": await auth.login("user_a", "usera@test.com", "Password123!"),
        "user_b": await auth.login("user_b", "userb@test.com", "Password123!"),
    }
    await auth.close()

    scanner = Scanner(base_url=BASE)
    result = await scanner.scan(endpoints, sessions)
    await scanner.close()

    check_ids = {f.check_id for f in result.findings}
    assert "API1_BOLA_NUMERIC" in check_ids
    assert "API5_BFLA_ADMIN" in check_ids
    assert "API3_MASS_ASSIGNMENT" in check_ids
    assert len(result.findings) >= 4
