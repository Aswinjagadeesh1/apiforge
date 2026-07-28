"""API7:2023 — Server-Side Request Forgery (SSRF).

Detects TWO classes of SSRF:

  IN-BAND  — the server fetches our URL and returns the fetched content in the
             response. Confirmed by finding cloud-metadata markers in the body
             (after stripping any mere echo of the URL we injected).

  BLIND    — the server fetches our URL but returns nothing useful in the
             response. Confirmed with an out-of-band (OOB) listener: we inject a
             unique URL pointing at a local catcher and check whether the
             target's backend actually connected to it.

FALSE-POSITIVE GUARDS:
  * A response that merely ECHOES the injected URL is NOT evidence — we remove
    the injected string before scanning for metadata content.
  * Blind detection relies on a real network callback to a unique token, so a
    reflected URL cannot fake it.

BLIND-MODE SCOPE (honest limitation):
  OOB detection only works when the TARGET can reach this machine (same host /
  network / Docker / lab). Against a remote internet target that cannot route
  back, blind SSRF is not detectable without a public collaborator server, which
  is out of scope for a local-first tool. In that case only in-band SSRF is
  found, and that limitation is stated rather than hidden.
"""
from __future__ import annotations

import re
from typing import Optional

from apiforge.checks.base import BaseCheck
from apiforge.executor.http_executor import HttpExecutor
from apiforge.models import Endpoint, Finding, Severity, UserSession

# Param names that commonly carry a URL the server will fetch. Includes value-
# based detection below, so a URL-valued field with an odd name (e.g.
# "mechanic_api") is still caught.
_URL_PARAM_HINTS = (
    "url", "uri", "link", "callback", "webhook", "target", "dest",
    "destination", "redirect", "redirect_uri", "next", "fetch", "load",
    "image_url", "imageurl", "img", "avatar", "file_url", "fileurl",
    "source", "src", "feed", "endpoint", "proxy", "domain", "host",
    "api", "server", "path", "site", "remote", "upstream", "origin",
)

_METADATA_URL = "http://169.254.169.254/latest/meta-data/"
_CONTROL_URL = "http://example.com/"

_METADATA_MARKERS = re.compile(
    r"ami-id|instance-id|iam/|security-credentials|meta-data/|hostname|"
    r"local-ipv4|public-keys|reservation-id",
    re.IGNORECASE,
)

# A value that looks like a URL or a host/path an app might fetch.
_URL_VALUE = re.compile(r"^\s*(https?://|//|www\.)", re.IGNORECASE)


def _url_params(endpoint: Endpoint) -> list[tuple[str, str]]:
    """Return (location, key) pairs for params that look URL-shaped — by NAME
    or by VALUE. Value-based detection catches URL fields with unusual names."""
    hits: list[tuple[str, str]] = []
    for k, v in (endpoint.query or {}).items():
        if any(h in k.lower() for h in _URL_PARAM_HINTS) or (
            isinstance(v, str) and _URL_VALUE.match(v or "")
        ):
            hits.append(("query", k))
    body = endpoint.body
    if isinstance(body, dict):
        for k, v in body.items():
            kl = str(k).lower()
            looks_url = isinstance(v, str) and _URL_VALUE.match(v or "")
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

        # -------------------- IN-BAND detection --------------------
        meta = await self._send_with(endpoint, executor, token, loc, key, _METADATA_URL)
        if meta is not None:
            meta_body = meta.text or ""
            # Remove any echo of the injected URL before scanning for real content.
            probe_body = meta_body.replace(_METADATA_URL, "")
            if _METADATA_MARKERS.search(probe_body):
                return self._finding(
                    endpoint=endpoint,
                    attack_response=meta,
                    description=(
                        f"The '{key}' parameter on {endpoint.method} {endpoint.path} is "
                        f"server-side fetchable (in-band SSRF). Pointing it at the cloud "
                        f"metadata service ({_METADATA_URL}) returned metadata content in "
                        f"the response, confirming SSRF that could expose instance "
                        f"credentials."
                    ),
                    poc_request=f"{endpoint.method} {endpoint.path}  ({key}={_METADATA_URL})",
                    poc_response=f"HTTP {meta.status_code}\n{self._truncate(meta_body)}",
                    remediation=(
                        f"On {endpoint.method} {endpoint.path}, do not fetch arbitrary "
                        f"user-supplied URLs from '{key}'. Enforce an allow-list of "
                        f"permitted hosts, block private/link-local ranges "
                        f"(169.254.0.0/16, 127.0.0.0/8, 10/8, 172.16/12, 192.168/16), and "
                        f"resolve-then-validate the destination before connecting."
                    ),
                )

        # -------------------- BLIND detection (OOB) --------------------
        # Only runs if the scan was started with an OOB listener attached to the
        # executor (executor.oob). Without it we cannot detect blind SSRF and we
        # do NOT guess — no false positives.
        oob = getattr(executor, "oob", None)
        if oob is not None:
            token_id = oob.new_token()
            probe = oob.probe_url(token_id)
            await self._send_with(endpoint, executor, token, loc, key, probe)
            # Give the target a moment to make the outbound call.
            import asyncio
            await asyncio.sleep(getattr(executor, "oob_wait", 2.0))
            if oob.was_hit(token_id):
                return self._finding(
                    endpoint=endpoint,
                    attack_response=None,
                    description=(
                        f"The '{key}' parameter on {endpoint.method} {endpoint.path} is "
                        f"server-side fetchable (blind SSRF). The server made an outbound "
                        f"request to a unique attacker-controlled URL ({probe}) — confirmed "
                        f"by an out-of-band interaction — even though the response body did "
                        f"not reveal the fetched content."
                    ),
                    poc_request=f"{endpoint.method} {endpoint.path}  ({key}={probe})",
                    poc_response=(
                        f"Out-of-band callback received at the APIForge listener for token "
                        f"'{token_id}'. The target's backend connected to our URL, proving "
                        f"it fetches attacker-supplied URLs."
                    ),
                    remediation=(
                        f"On {endpoint.method} {endpoint.path}, restrict '{key}' to an "
                        f"allow-list of trusted hosts and block private/link-local ranges. "
                        f"Validate the resolved IP (not just the hostname) before the server "
                        f"connects, and disable unnecessary outbound network access from the "
                        f"service."
                    ),
                )
        return None
