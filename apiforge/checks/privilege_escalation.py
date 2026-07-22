"""API5:2023 — Vertical Privilege Escalation via role-aware BFLA testing.

Unlike keyword-based BFLA (which guesses admin endpoints from the path), this
check uses a real admin account as a baseline:

  1. BASELINE  — admin user calls the endpoint. If admin gets 2xx, the endpoint
                 is a genuine, working (likely privileged) function.
  2. ATTACK    — the regular user calls the SAME endpoint with their token.
  3. COMPARE   — if the regular user also gets 2xx (not 401/403), a lower-
                 privilege user performed a function an admin can perform:
                 vertical privilege escalation.

This requires an admin session. It only runs when the config provides an
'admin' user, so it's opt-in and never breaks configs without one.

Config (in users.json):
    "user_admin": { "email": "admin@site.com", "password": "..." }
The CLI logs this in as the 'admin' session when present.
"""
from __future__ import annotations

from typing import Optional

from apiforge.checks.base import BaseCheck
from apiforge.executor.http_executor import HttpExecutor
from apiforge.models import Endpoint, Finding, Severity, UserSession

# State-changing methods matter most (create/update/delete), but we test GET too
# since reading admin-only data is also escalation.
_TESTABLE = ("GET", "POST", "PUT", "PATCH", "DELETE")


class PrivilegeEscalationCheck(BaseCheck):
    check_id = "API5_PRIV_ESCALATION"
    name = "Vertical Privilege Escalation (role-aware)"
    owasp_category = "API5:2023 Broken Function Level Authorization"
    cwe = "CWE-285"
    severity = Severity.HIGH
    cvss_score = 8.1

    ADMIN_HINTS = ("admin", "manage", "management", "internal",
                   "moderat", "superuser", "privileg", "all", "delete")

    def is_applicable(self, endpoint: Endpoint) -> bool:
        if endpoint.method not in _TESTABLE:
            return False
        # Only test endpoints that LOOK administrative — combining path
        # heuristics with the role-aware confirmation avoids flagging normal
        # authenticated endpoints (dashboard, own vehicles) as escalation.
        p = endpoint.path.lower()
        return any(h in p for h in self.ADMIN_HINTS)

    async def run(
        self,
        endpoint: Endpoint,
        sessions: dict[str, UserSession],
        executor: HttpExecutor,
    ) -> Optional[Finding]:
        admin = sessions.get("admin")
        regular = sessions.get("user_a")

        # Only runs when an admin session exists (opt-in).
        if not (admin and admin.authenticated and admin.token):
            return None
        if not (regular and regular.authenticated and regular.token):
            return None

        # 1. BASELINE: does the admin successfully use this endpoint?
        admin_resp = await executor.send(
            endpoint.method, endpoint.path, token=admin.token,
            headers=endpoint.headers, query=endpoint.query, body=endpoint.body,
        )
        if admin_resp is None or not (200 <= admin_resp.status_code < 300):
            return None  # not a working function for admin → nothing to escalate to

        # 2. CONTROL: does a garbage/no token get properly rejected? Confirms the
        #    endpoint enforces auth at all (guards against "public endpoint" FPs).
        anon_resp = await executor.send(
            endpoint.method, endpoint.path, token="invalid.control.token",
            headers=endpoint.headers, query=endpoint.query, body=endpoint.body,
        )
        if anon_resp is None:
            return None
        if 200 <= anon_resp.status_code < 300:
            return None  # endpoint is effectively public → not an escalation issue

        # 3. ATTACK: the regular user hits the same endpoint.
        reg_resp = await executor.send(
            endpoint.method, endpoint.path, token=regular.token,
            headers=endpoint.headers, query=endpoint.query, body=endpoint.body,
        )
        if reg_resp is None:
            return None

        # Guard: the regular user must receive MEANINGFUL data, not an empty
        # result. An empty list/zero-count response is weak evidence — the
        # endpoint let them in but exposed nothing, so we don't flag it.
        body = reg_resp.text.strip()
        looks_empty = (
            len(body) < 30
            or '"count":0' in body.replace(" ", "")
            or '"count": 0' in body
            or body in ("[]", "{}", '{"data":[]}')
            or '":[]' in body.replace(" ", "") and len(body) < 80
        )

        # 4. COMPARE: admin succeeded, anon was blocked, but regular ALSO succeeded
        #    with real data → a lower-privilege user performed an admin-capable
        #    function AND obtained privileged content.
        if 200 <= reg_resp.status_code < 300 and not looks_empty:
            return self._finding(
                endpoint=endpoint,
                attack_response=reg_resp,
                description=(
                    f"A regular (non-admin) user successfully performed "
                    f"{endpoint.method} {endpoint.path}, which the admin account "
                    f"can also perform and which rejects unauthenticated requests "
                    f"(admin: HTTP {admin_resp.status_code}, anonymous: "
                    f"HTTP {anon_resp.status_code}, regular user: "
                    f"HTTP {reg_resp.status_code}). The endpoint enforces "
                    f"authentication but not role-based authorization, allowing "
                    f"vertical privilege escalation."
                ),
                poc_request=(
                    f"{endpoint.method} {endpoint.path}\n"
                    f"Authorization: <REGULAR_USER_TOKEN>\n"
                    f"(admin can do this; anonymous is blocked; regular user "
                    f"should be blocked but is not)"
                ),
                poc_response=f"HTTP {reg_resp.status_code}\n{self._truncate(reg_resp.text)}",
                remediation=(
                    "Enforce role-based access control (RBAC) at the function "
                    "level on the server. Verify the caller's role/permissions "
                    "before executing privileged operations; return 403 Forbidden "
                    "for users whose role does not permit the action. Do not rely "
                    "on authentication alone or on the client hiding the endpoint."
                ),
            )
        return None
