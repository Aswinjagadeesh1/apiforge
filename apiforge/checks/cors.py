"""CORS Misconfiguration (maps to API8:2023 Security Misconfiguration).

Logic:
  1. Send a request with a forged, attacker-controlled Origin header.
  2. Inspect the CORS response headers.
  3. Flag the dangerous combinations:
       - Access-Control-Allow-Origin reflects the attacker origin AND
         Access-Control-Allow-Credentials: true   (worst case: credentialed
         cross-origin reads by any site)
       - Access-Control-Allow-Origin: *  AND  Allow-Credentials: true
         (invalid but some servers emit it; still worth flagging)

False-positive guard: a wildcard ACAO WITHOUT credentials is normal for public
APIs and is NOT flagged. We only flag reflection-with-credentials or the
illegal wildcard+credentials pairing.
"""
from __future__ import annotations

from typing import Optional

from apiforge.checks.base import BaseCheck
from apiforge.executor.http_executor import HttpExecutor
from apiforge.models import Endpoint, Finding, Severity, UserSession

_EVIL_ORIGIN = "https://apiforge-cors-probe.example"


class CORSMisconfigurationCheck(BaseCheck):
    check_id = "API8_CORS_MISCONFIG"
    name = "CORS Misconfiguration"
    owasp_category = "API8:2023 Security Misconfiguration"
    cwe = "CWE-942"
    severity = Severity.MEDIUM
    cvss_score = 6.5

    def is_applicable(self, endpoint: Endpoint) -> bool:
        # Only meaningful for endpoints that return data to a browser context.
        return endpoint.method in ("GET", "POST")

    async def run(
        self,
        endpoint: Endpoint,
        sessions: dict[str, UserSession],
        executor: HttpExecutor,
    ) -> Optional[Finding]:
        user = sessions.get("user_a") or sessions.get("user_admin")
        token = user.token if (user and user.authenticated) else None

        headers = dict(endpoint.headers or {})
        headers["Origin"] = _EVIL_ORIGIN

        resp = await executor.send(
            method=endpoint.method, path=endpoint.path, token=token,
            headers=headers, query=endpoint.query,
        )
        if resp is None:
            return None

        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()

        reflects_origin = acao == _EVIL_ORIGIN
        wildcard = acao == "*"
        creds = acac == "true"

        problem = None
        if reflects_origin and creds:
            problem = (
                f"reflects the attacker Origin ({_EVIL_ORIGIN}) in "
                f"Access-Control-Allow-Origin AND sets Access-Control-Allow-Credentials: "
                f"true"
            )
            self.severity = Severity.HIGH
            self.cvss_score = 7.5
        elif reflects_origin:
            problem = (
                f"reflects the attacker Origin ({_EVIL_ORIGIN}) in "
                f"Access-Control-Allow-Origin without validating it"
            )
        elif wildcard and creds:
            problem = (
                "returns Access-Control-Allow-Origin: * together with "
                "Access-Control-Allow-Credentials: true (an unsafe, non-compliant "
                "combination)"
            )

        if not problem:
            return None

        return self._finding(
            endpoint=endpoint,
            attack_response=resp,
            description=(
                f"{endpoint.method} {endpoint.path} {problem}. This lets a malicious "
                f"website read authenticated responses from this endpoint in a victim's "
                f"browser, enabling cross-origin data theft."
            ),
            poc_request=(
                f"{endpoint.method} {endpoint.path}\nOrigin: {_EVIL_ORIGIN}"
            ),
            poc_response=(
                f"HTTP {resp.status_code}\n"
                f"Access-Control-Allow-Origin: {acao or '(none)'}\n"
                f"Access-Control-Allow-Credentials: {acac or '(none)'}"
            ),
            remediation=(
                f"On {endpoint.method} {endpoint.path}, validate the Origin against a "
                f"strict server-side allow-list of trusted domains instead of reflecting "
                f"it. Never combine a reflected or wildcard Access-Control-Allow-Origin "
                f"with Access-Control-Allow-Credentials: true."
            ),
        )
