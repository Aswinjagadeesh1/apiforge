"""Async HTTP executor.

A thin wrapper around httpx that all checks share, so token injection, timeouts,
and error handling live in one place.
"""
from __future__ import annotations

from typing import Any, Optional

import httpx


class HttpExecutor:
    def __init__(self, base_url: str, timeout: float = 15.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.client = httpx.AsyncClient(timeout=timeout)

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
            h["Authorization"] = f"Bearer {token}"

        try:
            return await self.client.request(
                method=method,
                url=url,
                headers=h,
                params=query or None,
                json=body if body is not None else None,
            )
        except httpx.HTTPError:
            return None  # network errors → treat as "no response"

    async def close(self) -> None:
        await self.client.aclose()
