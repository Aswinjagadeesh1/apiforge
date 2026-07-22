"""Base class every security check inherits from.

A check declares metadata (id, OWASP category, CWE, severity, CVSS) and
implements two methods:
  - is_applicable(endpoint): cheap filter, does this check apply here?
  - run(endpoint, sessions, executor): actually test it, return a Finding or None.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from apiforge.executor.http_executor import HttpExecutor, raw_request, raw_response
from apiforge.models import Endpoint, Finding, Severity, UserSession


class BaseCheck(ABC):
    check_id: str = "BASE"
    name: str = "Base Check"
    owasp_category: str = ""
    cwe: str = ""
    severity: Severity = Severity.INFO
    cvss_score: float = 0.0

    @abstractmethod
    def is_applicable(self, endpoint: Endpoint) -> bool:
        ...

    @abstractmethod
    async def run(
        self,
        endpoint: Endpoint,
        sessions: dict[str, UserSession],
        executor: HttpExecutor,
    ) -> Optional[Finding]:
        ...

    # ----- helper so subclasses build findings consistently -----
    def _finding(
        self,
        endpoint: Endpoint,
        description: str,
        poc_request: str,
        poc_response: str,
        remediation: str,
        attack_response=None,
    ) -> Finding:
        # If the check hands us the real httpx response of the attack request,
        # build a reproducible PoC from the ACTUAL request/response sent.
        if attack_response is not None:
            try:
                poc_request = raw_request(attack_response)
                poc_response = raw_response(attack_response)
            except Exception:
                pass  # fall back to the provided strings
        return Finding(
            check_id=self.check_id,
            title=self.name,
            severity=self.severity,
            owasp_category=self.owasp_category,
            cwe=self.cwe,
            cvss_score=self.cvss_score,
            method=endpoint.method,
            endpoint=endpoint.path,
            description=description,
            poc_request=poc_request,
            poc_response=poc_response,
            remediation=remediation,
        )

    @staticmethod
    def _truncate(text: str, limit: int = 400) -> str:
        text = text or ""
        return text if len(text) <= limit else text[:limit] + " …[truncated]"
