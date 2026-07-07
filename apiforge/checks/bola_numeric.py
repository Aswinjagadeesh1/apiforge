"""API1:2023 — Broken Object Level Authorization (BOLA) via numeric ID swap.

Logic:
  1. Request the resource as User A (baseline). If A can't access it (non-200),
     skip — we have no confirmed object to test against.
  2. Replay the identical request with User B's token.
  3. If B receives 200 with a body identical (or near-identical) to A's, the
     server failed to enforce object ownership → BOLA.

The identical-body comparison is the false-positive guard: we only flag when
User B receives byte-for-byte the same data User A received.
"""
from __future__ import annotations

from typing import Optional

from apiforge.checks.base import BaseCheck
from apiforge.executor.http_executor import HttpExecutor
from apiforge.models import Endpoint, Finding, Severity, UserSession


class BolaNumericCheck(BaseCheck):
    check_id = "API1_BOLA_NUMERIC"
    name = "BOLA via Numeric Object ID"
    owasp_category = "API1:2023 Broken Object Level Authorization"
    cwe = "CWE-639"
    severity = Severity.HIGH
    cvss_score = 7.5

    def is_applicable(self, endpoint: Endpoint) -> bool:
        # Only GET/PUT/DELETE endpoints with a numeric id in the path.
        return endpoint.method in ("GET", "PUT", "DELETE") and bool(
            endpoint.numeric_ids()
        )

    async def run(
        self,
        endpoint: Endpoint,
        sessions: dict[str, UserSession],
        executor: HttpExecutor,
    ) -> Optional[Finding]:
        user_a = sessions.get("user_a")
        user_b = sessions.get("user_b")
        if not (user_a and user_b and user_a.authenticated and user_b.authenticated):
            return None

        # Baseline: User A accesses their own resource.
        resp_a = await executor.send(
            method=endpoint.method,
            path=endpoint.path,
            token=user_a.token,
            headers=endpoint.headers,
            query=endpoint.query,
            body=endpoint.body,
        )
        if resp_a is None or resp_a.status_code != 200 or not resp_a.text.strip():
            return None

        # Attack: User B accesses User A's resource.
        resp_b = await executor.send(
            method=endpoint.method,
            path=endpoint.path,
            token=user_b.token,
            headers=endpoint.headers,
            query=endpoint.query,
            body=endpoint.body,
        )
        if resp_b is None:
            return None

        # Vuln signal: B gets 200 and the same data A got.
        if resp_b.status_code == 200 and resp_b.text.strip() == resp_a.text.strip():
            return self._finding(
                endpoint=endpoint,
                description=(
                    f"User B successfully retrieved User A's resource at "
                    f"'{endpoint.path}'. The server returned an identical response "
                    f"body to both users, indicating no object-level ownership "
                    f"check is enforced."
                ),
                poc_request=(
                    f"{endpoint.method} {endpoint.path}\n"
                    f"Authorization: Bearer <USER_B_TOKEN>\n"
                    f"(User B is not the owner of this object)"
                ),
                poc_response=(
                    f"HTTP {resp_b.status_code}\n"
                    f"{self._truncate(resp_b.text)}"
                ),
                remediation=(
                    "Enforce object-level authorization on the server side. For "
                    "every request that references an object by ID, verify the "
                    "authenticated user owns or is permitted to access that object "
                    "before returning data. Prefer non-sequential identifiers "
                    "(UUIDs) to reduce enumeration risk."
                ),
            )
        return None
