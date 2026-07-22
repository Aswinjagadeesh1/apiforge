"""API5:2023 — Broken Function Level Authorization (BFLA).

Logic:
  1. Identify endpoints whose path suggests privileged/admin functionality.
  2. Call them with a regular (non-admin) user's token.
  3. If the server responds 200/201, function-level authorization is missing —
     a normal user reached an admin function.
"""
from __future__ import annotations

from typing import Optional

from apiforge.checks.base import BaseCheck
from apiforge.executor.http_executor import HttpExecutor
from apiforge.models import Endpoint, Finding, Severity, UserSession


class BFLACheck(BaseCheck):
    check_id = "API5_BFLA_ADMIN"
    name = "BFLA — Admin Function Reachable by Regular User"
    owasp_category = "API5:2023 Broken Function Level Authorization"
    cwe = "CWE-285"
    severity = Severity.HIGH
    cvss_score = 7.5

    ADMIN_KEYWORDS = (
        "admin",
        "manage",
        "internal",
        "moderat",
        "superuser",
        "privileg",
    )

    def is_applicable(self, endpoint: Endpoint) -> bool:
        p = endpoint.path.lower()
        return any(kw in p for kw in self.ADMIN_KEYWORDS)

    async def run(
        self,
        endpoint: Endpoint,
        sessions: dict[str, UserSession],
        executor: HttpExecutor,
    ) -> Optional[Finding]:
        # Use the lower-privileged actor. user_a is treated as the regular user.
        user = sessions.get("user_a")
        if not (user and user.authenticated):
            return None

        resp = await executor.send(
            method=endpoint.method,
            path=endpoint.path,
            token=user.token,
            headers=endpoint.headers,
            query=endpoint.query,
            body=endpoint.body,
        )
        if resp is None:
            return None

        if resp.status_code in (200, 201):
            return self._finding(
                endpoint=endpoint,
                attack_response=resp,
                description=(
                    f"A regular (non-admin) user reached the privileged endpoint "
                    f"'{endpoint.path}' and received HTTP {resp.status_code}. "
                    f"Function-level authorization appears to be missing or not "
                    f"enforced for this administrative function."
                ),
                poc_request=(
                    f"{endpoint.method} {endpoint.path}\n"
                    f"Authorization: Bearer <REGULAR_USER_TOKEN>"
                ),
                poc_response=f"HTTP {resp.status_code}\n{self._truncate(resp.text)}",
                remediation=(
                    f"Enforce a server-side role check on {endpoint.method} "
                    f"{endpoint.path}: require the caller to hold the administrative "
                    f"role before executing this function, deny by default, and "
                    f"return 403 for non-admin users."
                ),
            )
        return None
