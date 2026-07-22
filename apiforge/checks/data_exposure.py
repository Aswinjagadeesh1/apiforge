"""API3:2023 — Sensitive Data / Excessive Data Exposure.

Logic:
  1. For GET endpoints, fetch the response as an authenticated user.
  2. Scan the JSON response for field names that should never be exposed
     (password hashes, secrets, tokens, national IDs, card data).
  3. Report any that appear.

False-positive guard: we match on structural field keys (e.g. "password":),
not loose substrings, to avoid flagging words like "password_reset_url".
"""
from __future__ import annotations

import re
from typing import Optional

from apiforge.checks.base import BaseCheck
from apiforge.executor.http_executor import HttpExecutor
from apiforge.models import Endpoint, Finding, Severity, UserSession


class SensitiveDataExposureCheck(BaseCheck):
    check_id = "API3_DATA_EXPOSURE"
    name = "Sensitive Data Exposure in Response"
    owasp_category = "API3:2023 Broken Object Property Level Authorization"
    cwe = "CWE-200"
    severity = Severity.MEDIUM
    cvss_score = 5.3

    SENSITIVE_KEYS = (
        "password",
        "passwd",
        "pwd",
        "hash",
        "salt",
        "secret",
        "ssn",
        "aadhaar",
        "aadhar",
        "pan",
        "creditcard",
        "credit_card",
        "card_number",
        "cvv",
        "private_key",
        "api_key",
        "apikey",
        "session_id",
        "refresh_token",
    )

    def is_applicable(self, endpoint: Endpoint) -> bool:
        return endpoint.method == "GET"

    async def run(
        self,
        endpoint: Endpoint,
        sessions: dict[str, UserSession],
        executor: HttpExecutor,
    ) -> Optional[Finding]:
        user = sessions.get("user_a")
        if not (user and user.authenticated):
            return None

        resp = await executor.send(
            method=endpoint.method,
            path=endpoint.path,
            token=user.token,
            headers=endpoint.headers,
            query=endpoint.query,
        )
        if resp is None or resp.status_code != 200:
            return None

        text = resp.text
        found: list[str] = []
        for key in self.SENSITIVE_KEYS:
            # Match a JSON key: "key" followed by a colon.
            if re.search(rf'["\']{re.escape(key)}["\']\s*:', text, re.IGNORECASE):
                found.append(key)

        if found:
            return self._finding(
                endpoint=endpoint,
                attack_response=resp,
                description=(
                    f"The response from '{endpoint.path}' contains sensitive field "
                    f"name(s): {', '.join(sorted(set(found)))}. Exposing these in "
                    f"API responses risks credential and PII leakage."
                ),
                poc_request=(
                    f"GET {endpoint.path}\nAuthorization: Bearer <USER_TOKEN>"
                ),
                poc_response=f"HTTP 200\n{self._truncate(text)}",
                remediation=(
                    f"Remove the sensitive field(s) "
                    f"{', '.join(sorted(set(found)))} from the {endpoint.path} "
                    f"response. Return only the attributes the client needs via an "
                    f"explicit output schema/serializer rather than the full object."
                ),
            )
        return None
