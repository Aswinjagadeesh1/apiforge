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
