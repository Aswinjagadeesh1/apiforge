"""API8:2023 — Security Misconfiguration (verbose error / debug disclosure).

Logic:
  1. Send a deliberately malformed request to the endpoint (broken JSON body
     for methods that take one; an unexpected query param otherwise).
  2. Inspect the response for stack traces, framework/server banners, file
     system paths, or debug markers that a hardened API should never leak.

False-positive guard: we only flag on strong, specific signals (traceback
keywords, language runtime markers, absolute file paths) — not on the mere
presence of the word "error".
"""
from __future__ import annotations

import re
from typing import Optional

from apiforge.checks.base import BaseCheck
from apiforge.executor.http_executor import HttpExecutor
from apiforge.models import Endpoint, Finding, Severity, UserSession

# Strong leakage signals. Each entry: (regex, human label).
_SIGNALS = [
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"\bat [\w.$]+\([\w.]+\.java:\d+\)", "Java stack trace"),
    (r"\b(?:Exception|Error) in \S+\.(?:php|rb|go|py|js) on line \d+", "source-file error"),
    (r"\.(?:java|py|rb|php|go|ts|js):\d+", "source-file:line reference"),
    (r"/(?:home|var|usr|opt|app|Users)/[\w./-]+\.(?:py|js|rb|php|java|go|ts)", "absolute source path"),
    (r"org\.springframework\.[\w.]+Exception", "Spring exception class"),
    (r"sqlalchemy\.exc\.|psycopg2\.|MySQLdb\.|ORA-\d{5}|SQLSTATE\[", "database driver error"),
    (r'"stack"\s*:\s*"', "JSON stack field"),
    (r"\bDEBUG\s*=\s*True\b", "debug mode enabled"),
    (r"Werkzeug Debugger|Whitmann|django\.core\.exceptions", "framework debug page"),
]

_SERVER_BANNER = re.compile(
    r"(?:^|\n)(?:Server|X-Powered-By|X-AspNet-Version|X-Runtime):\s*(.+)",
    re.IGNORECASE,
)


class SecurityMisconfigurationCheck(BaseCheck):
    check_id = "API8_VERBOSE_ERRORS"
    name = "Security Misconfiguration — Verbose Error Disclosure"
    owasp_category = "API8:2023 Security Misconfiguration"
    cwe = "CWE-209"
    severity = Severity.MEDIUM
    cvss_score = 5.3

    def is_applicable(self, endpoint: Endpoint) -> bool:
        # Applies broadly; every endpoint can be probed for verbose errors.
        return True

    async def run(
        self,
        endpoint: Endpoint,
        sessions: dict[str, UserSession],
        executor: HttpExecutor,
    ) -> Optional[Finding]:
        user = sessions.get("user_a") or sessions.get("user_admin")
        token = user.token if (user and user.authenticated) else None

        # Craft a malformed request likely to trigger an unhandled error.
        if endpoint.method in ("POST", "PUT", "PATCH"):
            # Send a body that is valid JSON but wrong types, plus a junk param.
            attack_body = {"__apiforge_probe__": {"nested": [1, 2, {"x": None}]}, "id": "\x00\uffff"}
            resp = await executor.send(
                method=endpoint.method, path=endpoint.path, token=token,
                headers=endpoint.headers, query={"debug": "1", "__probe": "'\"<>"},
                body=attack_body,
            )
        else:
            resp = await executor.send(
                method=endpoint.method, path=endpoint.path, token=token,
                headers=endpoint.headers,
                query={**endpoint.query, "id": "'\"<>\x00", "__probe": "../../etc/passwd"},
            )

        if resp is None:
            return None

        body = resp.text or ""
        # Build a headers blob so the banner regex can see response headers too.
        header_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        haystack = header_blob + "\n" + body

        hits: list[str] = []
        for pattern, label in _SIGNALS:
            if re.search(pattern, body):
                hits.append(label)

        banner = None
        m = _SERVER_BANNER.search(header_blob)
        if m and re.search(r"\d", m.group(1) or ""):
            # Only flag a banner that leaks a version number.
            banner = m.group(1).strip()

        # Only STRONG content signals are per-endpoint findings. A version banner
        # alone (e.g. Server: openresty/1.27.1) is a single global config issue,
        # not a vuln on every endpoint — reporting it per-endpoint inflates the
        # report, so it is intentionally NOT flagged here.
        if not hits:
            return None

        detail = [f"leaked: {', '.join(sorted(set(hits)))}"]
        if banner:
            detail.append(f"version banner: {banner}")

        return self._finding(
            endpoint=endpoint,
            attack_response=resp,
            description=(
                f"A malformed request to {endpoint.method} {endpoint.path} caused the "
                f"server to return internal detail in the response ({'; '.join(detail)}). "
                f"Verbose errors reveal the technology stack and code structure, helping "
                f"an attacker tailor further attacks."
            ),
            poc_request=f"{endpoint.method} {endpoint.path}  (malformed input)",
            poc_response=f"HTTP {resp.status_code}\n{self._truncate(body)}",
            remediation=(
                f"Configure {endpoint.method} {endpoint.path} (and the application's "
                f"global error handler) to return a generic error response. Disable debug "
                f"mode in production, strip stack traces and framework/version banners, and "
                f"log the detail server-side instead of returning it to the client."
            ),
        )
