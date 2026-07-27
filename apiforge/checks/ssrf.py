"""API7:2023 — Server-Side Request Forgery (SSRF).

Logic:
  1. Find request parameters that look like they take a URL (url, uri,
     callback, webhook, image_url, target, dest, redirect, fetch, ...).
  2. Replace them with attacker-controlled internal targets (cloud metadata
     endpoint, localhost) and send the request.
  3. Flag if the response indicates the server actually fetched the target
     (metadata markers, connection-level differences vs a benign control URL).

False-positive guard: we compare the injected-internal-URL response against a
benign-external-URL control. We only flag when the internal target produces a
materially different, fetch-consistent response (metadata content, or a clear
200/timeout pattern the control did not produce).
"""
from __future__ import annotations

import re
from typing import Optional

from apiforge.checks.base import BaseCheck
from apiforge.executor.http_executor import HttpExecutor
from apiforge.models import Endpoint, Finding, Severity, UserSession

# Param names that commonly carry a URL the server will fetch.
_URL_PARAM_HINTS = (
    "url", "uri", "link", "callback", "webhook", "target", "dest",
    "destination", "redirect", "redirect_uri", "next", "fetch", "load",
    "image_url", "imageurl", "img", "avatar", "file_url", "fileurl",
    "source", "src", "feed", "endpoint", "proxy", "domain", "host",
)

# Internal targets that should be unreachable / meaningful only server-side.
_METADATA_URL = "http://169.254.169.254/latest/meta-data/"
_LOCALHOST_URL = "http://127.0.0.1:80/"
_CONTROL_URL = "http://example.com/"  # benign external control

# Response markers that strongly indicate the metadata endpoint was reached.
_METADATA_MARKERS = re.compile(
    r"ami-id|instance-id|iam/|security-credentials|meta-data/|hostname|"
    r"local-ipv4|public-keys|reservation-id",
    re.IGNORECASE,
)


def _url_params(endpoint: Endpoint) -> list[tuple[str, str]]:
    """Return (location, key) pairs for params that look URL-shaped.
    location is 'query' or 'body'."""
    hits: list[tuple[str, str]] = []
    for k in (endpoint.query or {}):
        if any(h in k.lower() for h in _URL_PARAM_HINTS):
            hits.append(("query", k))
    body = endpoint.body
    if isinstance(body, dict):
        for k, v in body.items():
            kl = str(k).lower()
            looks_url = isinstance(v, str) and re.match(r"https?://", v or "")
            if any(h in kl for h in _URL_PARAM_HINTS) or looks_url:
                hits.append(("body", k))
    return hits


class SSRFCheck(BaseCheck):
    check_id = "API7_SSRF"
    name = "Server-Side Request Forgery (SSRF)"
    owasp_category = "API7:2023 Server-Side Request Forgery"
    cwe = "CWE-918"
    severity = Severity.HIGH
    cvss_score = 8.6

    def is_applicable(self, endpoint: Endpoint) -> bool:
        return bool(_url_params(endpoint))

    async def _send_with(self, endpoint, executor, token, loc, key, value):
        query = dict(endpoint.query or {})
        body = dict(endpoint.body) if isinstance(endpoint.body, dict) else endpoint.body
        if loc == "query":
            query[key] = value
        elif isinstance(body, dict):
            body[key] = value
        return await executor.send(
            method=endpoint.method, path=endpoint.path, token=token,
            headers=endpoint.headers, query=query, body=body,
        )

    async def run(
        self,
        endpoint: Endpoint,
        sessions: dict[str, UserSession],
        executor: HttpExecutor,
    ) -> Optional[Finding]:
        user = sessions.get("user_a") or sessions.get("user_admin")
        token = user.token if (user and user.authenticated) else None

        params = _url_params(endpoint)
        if not params:
            return None

        loc, key = params[0]

        # 1) benign control
        control = await self._send_with(endpoint, executor, token, loc, key, _CONTROL_URL)
        # 2) cloud metadata target
        meta = await self._send_with(endpoint, executor, token, loc, key, _METADATA_URL)

        if meta is None:
            return None

        meta_body = meta.text or ""

        # Strongest signal: metadata content reflected back.
        if _METADATA_MARKERS.search(meta_body):
            return self._finding(
                endpoint=endpoint,
                attack_response=meta,
                description=(
                    f"The '{key}' parameter on {endpoint.method} {endpoint.path} is "
                    f"server-side fetchable. Pointing it at the cloud metadata service "
                    f"({_METADATA_URL}) returned metadata content, confirming SSRF that "
                    f"could expose instance credentials."
                ),
                poc_request=f"{endpoint.method} {endpoint.path}  ({key}={_METADATA_URL})",
                poc_response=f"HTTP {meta.status_code}\n{self._truncate(meta_body)}",
                remediation=(
                    f"On {endpoint.method} {endpoint.path}, do not fetch arbitrary "
                    f"user-supplied URLs from '{key}'. Enforce an allow-list of permitted "
                    f"hosts, block requests to private/link-local ranges "
                    f"(169.254.0.0/16, 127.0.0.0/8, 10/8, 172.16/12, 192.168/16), and "
                    f"resolve-then-validate the destination before connecting."
                ),
            )

        # Secondary signal: internal localhost fetch behaves unlike the control.
        local = await self._send_with(endpoint, executor, token, loc, key, _LOCALHOST_URL)
        if local is not None and control is not None:
            # A clear status divergence where localhost succeeds/reaches but the
            # external control is rejected can indicate SSRF — flag cautiously.
            if (local.status_code < 500 and control.status_code >= 400
                    and local.status_code != control.status_code):
                return self._finding(
                    endpoint=endpoint,
                    attack_response=local,
                    description=(
                        f"The '{key}' parameter on {endpoint.method} {endpoint.path} "
                        f"appears to trigger a server-side request. An internal target "
                        f"({_LOCALHOST_URL}) produced HTTP {local.status_code} while a "
                        f"benign external URL produced HTTP {control.status_code}, "
                        f"suggesting the server fetches attacker-controlled URLs. "
                        f"Verify manually before reporting."
                    ),
                    poc_request=f"{endpoint.method} {endpoint.path}  ({key}={_LOCALHOST_URL})",
                    poc_response=f"HTTP {local.status_code}\n{self._truncate(local.text)}",
                    remediation=(
                        f"On {endpoint.method} {endpoint.path}, restrict '{key}' to an "
                        f"allow-list of hosts and block private/link-local address ranges. "
                        f"Validate the resolved IP, not just the hostname, before the "
                        f"server makes the request."
                    ),
                )
        return None
