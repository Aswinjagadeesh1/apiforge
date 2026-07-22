"""API4:2023 — Unrestricted Resource Consumption (missing rate limiting)."""
from __future__ import annotations

import asyncio
from typing import Optional

from apiforge.checks.base import BaseCheck
from apiforge.executor.http_executor import HttpExecutor
from apiforge.models import Endpoint, Finding, Severity, UserSession

SENSITIVE_KEYWORDS = (
    "login", "signin", "auth", "otp", "verify", "reset",
    "forgot", "password", "signup", "register", "token",
)

BURST = 15


class RateLimitingCheck(BaseCheck):
    check_id = "API4_NO_RATE_LIMIT"
    name = "Unrestricted Resource Consumption — Missing Rate Limiting"
    owasp_category = "API4:2023 Unrestricted Resource Consumption"
    cwe = "CWE-307"
    severity = Severity.MEDIUM
    cvss_score = 5.3

    def is_applicable(self, endpoint: Endpoint) -> bool:
        p = endpoint.path.lower()
        return endpoint.method == "POST" and any(kw in p for kw in SENSITIVE_KEYWORDS)

    async def run(
        self,
        endpoint: Endpoint,
        sessions: dict[str, UserSession],
        executor: HttpExecutor,
    ) -> Optional[Finding]:
        async def one():
            return await executor.send(
                method=endpoint.method,
                path=endpoint.path,
                headers=endpoint.headers,
                query=endpoint.query,
                body=endpoint.body,
            )

        responses = await asyncio.gather(*[one() for _ in range(BURST)])
        responses = [r for r in responses if r is not None]
        if not responses:
            return None

        statuses = [r.status_code for r in responses]
        throttled = any(s in (429, 503) for s in statuses)
        processed = sum(1 for s in statuses if s < 500 and s != 404)

        if not throttled and processed >= BURST - 2:
            return self._finding(
                endpoint=endpoint,
                description=(
                    f"The sensitive endpoint '{endpoint.path}' accepted "
                    f"{len(responses)} rapid requests without any rate limiting "
                    f"(no HTTP 429 responses). This enables brute-force attacks "
                    f"on credentials/OTPs and resource-exhaustion abuse."
                ),
                poc_request=(
                    f"{endpoint.method} {endpoint.path}  x{len(responses)} rapid requests\n"
                    f"Observed status codes: {sorted(set(statuses))}"
                ),
                poc_response=(
                    f"No 429 (Too Many Requests) returned across "
                    f"{len(responses)} requests."
                ),
                remediation=(
                    f"Apply rate limiting to {endpoint.method} {endpoint.path} "
                    f"(per-IP and per-account quotas, backoff, CAPTCHA after "
                    f"repeated failures) and return HTTP 429 when exceeded. This "
                    f"endpoint accepted {len(responses)} rapid requests with no "
                    f"throttling."
                ),
            )
        return None
