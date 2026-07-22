"""Async HTTP executor.

Wraps httpx so token injection, timeouts, and error handling live in one place.
Supports a custom auth header (default: Authorization: Bearer <token>), so APIs
using non-standard headers like x-access-token also work.
"""
from __future__ import annotations

from typing import Any, Optional

import httpx


class HttpExecutor:
    def __init__(
        self,
        base_url: str,
        auth_header: str = "Authorization",
        auth_scheme: str = "Bearer",
        timeout: float = 15.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth_header = auth_header
        self.auth_scheme = auth_scheme
        self.client = httpx.AsyncClient(timeout=timeout)

    def _auth_value(self, token: str) -> str:
        # If a scheme is set (e.g. "Bearer"), prefix it; otherwise send raw token.
        return f"{self.auth_scheme} {token}" if self.auth_scheme else token

    async def send(
        self,
        method: str,
        path: str,
        token: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
        query: Optional[dict[str, str]] = None,
        body: Optional[Any] = None,
    ) -> Optional[httpx.Response]:
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        h: dict[str, str] = dict(headers or {})
        if token:
            h[self.auth_header] = self._auth_value(token)

        try:
            return await self.client.request(
                method=method,
                url=url,
                headers=h,
                params=query or None,
                json=body if body is not None else None,
            )
        except httpx.HTTPError:
            return None

    async def close(self) -> None:
        await self.client.aclose()


# --- PoC capture helpers: format the REAL request/response actually sent ---
def raw_request(response) -> str:
    """Format the actual httpx request that produced `response` as a raw HTTP
    request string — real method, path, headers (incl. the real auth token
    sent) and body. Used to build reproducible PoCs."""
    r = getattr(response, "request", None)
    if r is None:
        return ""
    url = r.url
    path = url.raw_path.decode() if isinstance(url.raw_path, (bytes, bytearray)) else str(url.raw_path)
    host = url.netloc.decode() if isinstance(url.netloc, (bytes, bytearray)) else (url.host or "")
    lines = [f"{r.method} {path} HTTP/1.1", f"Host: {host}"]
    for k, v in r.headers.items():
        if k.lower() == "host":
            continue
        lines.append(f"{k}: {v}")
    out = "\n".join(lines)
    body = r.content or b""
    try:
        body_s = body.decode("utf-8", "replace")
    except Exception:
        body_s = ""
    if body_s.strip():
        out += "\n\n" + body_s
    return out


def raw_response(response, limit: int = 800) -> str:
    """Format the actual server response (status, key headers, truncated body)."""
    reason = getattr(response, "reason_phrase", "") or ""
    lines = [f"HTTP {response.status_code} {reason}".rstrip()]
    for k in ("content-type", "content-length", "server"):
        if k in response.headers:
            lines.append(f"{k.title()}: {response.headers[k]}")
    body = response.text or ""
    if len(body) > limit:
        body = body[:limit] + " …[truncated]"
    out = "\n".join(lines)
    if body.strip():
        out += "\n\n" + body
    return out
