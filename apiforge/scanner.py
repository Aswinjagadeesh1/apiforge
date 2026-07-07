"""Scanner orchestrator — the engine that ties parser, auth, checks together."""
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
    ) -> None:
        self.executor = HttpExecutor(base_url)
        self.checks = checks if checks is not None else ALL_CHECKS

    async def scan(
        self,
        endpoints: list[Endpoint],
        sessions: dict[str, UserSession],
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> ScanResult:
        result = ScanResult()

        # Pre-compute the applicable (endpoint, check) work items.
        work: list[tuple[Endpoint, BaseCheck]] = []
        for ep in endpoints:
            for check in self.checks:
                try:
                    if check.is_applicable(ep):
                        work.append((ep, check))
                except Exception as exc:  # a bad check shouldn't kill the scan
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

        result.endpoints_scanned = len(endpoints)
        return result

    async def close(self) -> None:
        await self.executor.close()
