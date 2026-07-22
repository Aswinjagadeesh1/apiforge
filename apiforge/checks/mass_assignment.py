"""API3:2023 — Mass Assignment / privilege-escalation field injection.

Logic:
  1. Target write endpoints (POST/PUT/PATCH) that carry a JSON body.
  2. Inject sensitive privilege fields (isAdmin, role, etc.) into the body.
  3. If the server accepts the request (200/201) AND reflects the injected
     field back in the response, it likely bound the attacker-controlled field
     to the object → mass assignment.
"""
from __future__ import annotations

from typing import Optional

from apiforge.checks.base import BaseCheck
from apiforge.executor.http_executor import HttpExecutor
from apiforge.models import Endpoint, Finding, Severity, UserSession


class MassAssignmentCheck(BaseCheck):
    check_id = "API3_MASS_ASSIGNMENT"
    name = "Mass Assignment — Privilege Field Injection"
    owasp_category = "API3:2023 Broken Object Property Level Authorization"
    cwe = "CWE-915"
    severity = Severity.HIGH
    cvss_score = 8.1

    INJECT_FIELDS: dict[str, object] = {
        "isAdmin": True,
        "is_admin": True,
        "admin": True,
        "role": "admin",
        "role_id": 1,
        "is_verified": True,
        "verified": True,
        "account_balance": 999999,
    }

    def is_applicable(self, endpoint: Endpoint) -> bool:
        return endpoint.method in ("POST", "PUT", "PATCH") and isinstance(
            endpoint.body, dict
        )

    async def run(
        self,
        endpoint: Endpoint,
        sessions: dict[str, UserSession],
        executor: HttpExecutor,
    ) -> Optional[Finding]:
        user = sessions.get("user_a")
        if not (user and user.authenticated):
            return None
        if not isinstance(endpoint.body, dict):
            return None

        injected = dict(endpoint.body)
        injected.update(self.INJECT_FIELDS)

        resp = await executor.send(
            method=endpoint.method,
            path=endpoint.path,
            token=user.token,
            headers=endpoint.headers,
            query=endpoint.query,
            body=injected,
        )
        if resp is None or resp.status_code not in (200, 201):
            return None

        lower = resp.text.lower()
        reflected = [
            f for f in self.INJECT_FIELDS if f.lower() in lower
        ]
        if reflected:
            return self._finding(
                endpoint=endpoint,
                attack_response=resp,
                description=(
                    f"The endpoint '{endpoint.path}' accepted unexpected "
                    f"privilege-related fields ({', '.join(reflected)}) in the "
                    f"request body and reflected them in the response. This "
                    f"suggests the server binds client-supplied fields directly "
                    f"to the object, enabling privilege escalation."
                ),
                poc_request=(
                    f"{endpoint.method} {endpoint.path}\n"
                    f"Authorization: Bearer <USER_TOKEN>\n"
                    f"Body includes injected fields: "
                    f"{', '.join(reflected)}"
                ),
                poc_response=f"HTTP {resp.status_code}\n{self._truncate(resp.text)}",
                remediation=(
                    f"On {endpoint.method} {endpoint.path}, stop binding the "
                    f"request body directly to the object. Bind an explicit "
                    f"allow-list of client-writable fields and reject or ignore the "
                    f"privileged field(s) accepted here ({', '.join(reflected)})."
                ),
            )
        return None
