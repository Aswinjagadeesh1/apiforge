"""Scanner orchestrator — ties parser, auth, checks together."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from apiforge.checks import ALL_CHECKS
from apiforge.checks.base import BaseCheck
from apiforge.executor.http_executor import HttpExecutor
from apiforge.models import Endpoint, Finding, UserSession


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    endpoints_scanned: int = 0
    checks_run: int = 0
    errors: list[str] = field(default_factory=list)


class Scanner:
    def __init__(
        self,
        base_url: str,
        checks: Optional[list[BaseCheck]] = None,
        auth_header: str = "Authorization",
        auth_scheme: str = "Bearer",
    ) -> None:
        self.executor = HttpExecutor(
            base_url, auth_header=auth_header, auth_scheme=auth_scheme
        )
        self.checks = checks if checks is not None else ALL_CHECKS

    async def scan(
        self,
        endpoints: list[Endpoint],
        sessions: dict[str, UserSession],
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> ScanResult:
        result = ScanResult()

        work: list[tuple[Endpoint, BaseCheck]] = []
        for ep in endpoints:
            for check in self.checks:
                try:
                    if check.is_applicable(ep):
                        work.append((ep, check))
                except Exception as exc:
                    result.errors.append(
                        f"{check.check_id} applicability on {ep.path}: {exc}"
                    )

        total = len(work)
        for i, (ep, check) in enumerate(work, 1):
            try:
                finding = await check.run(ep, sessions, self.executor)
                if finding:
                    result.findings.append(finding)
            except Exception as exc:
                result.errors.append(f"{check.check_id} on {ep.path}: {exc}")
            result.checks_run += 1
            if on_progress:
                on_progress(i, total)

        # Deduplicate findings by (check_id, method, endpoint).
        seen = set()
        unique = []
        for f in result.findings:
            key = (f.check_id, f.method, f.endpoint)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        result.findings = unique

        # Cross-check dedup: BFLA and privilege-escalation catch the SAME root
        # flaw (an admin function reachable by a regular user). When both fire on
        # the same endpoint, keep only privilege-escalation — it is the stronger,
        # more specific finding (it also verifies the unauth path returns 401).
        priv_eps = {
            (f.method, f.endpoint)
            for f in result.findings
            if f.check_id == "API5_PRIV_ESCALATION"
        }
        result.findings = [
            f for f in result.findings
            if not (
                f.check_id == "API5_BFLA_ADMIN"
                and (f.method, f.endpoint) in priv_eps
            )
        ]

        result.endpoints_scanned = len(endpoints)
        return result

    async def close(self) -> None:
        await self.executor.close()
