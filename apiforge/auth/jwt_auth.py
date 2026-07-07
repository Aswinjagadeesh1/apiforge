"""JWT / bearer-token authenticator.

Logs a user in against a configurable login endpoint and extracts the bearer
token from the response. Token location varies by API, so we search a list of
common JSON keys and also support a dotted json_path override.
"""
from __future__ import annotations

from typing import Any, Optional

import httpx

from apiforge.models import UserSession

# Common keys APIs use to return a token.
_TOKEN_KEYS = ("token", "access_token", "accessToken", "jwt", "id_token", "authToken")


def _dig(data: Any, dotted: str) -> Optional[str]:
    """Follow a dotted path like 'data.token' into a nested dict."""
    cur = data
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return str(cur) if cur is not None else None


def _extract_token(data: Any, json_path: Optional[str]) -> Optional[str]:
    if json_path:
        found = _dig(data, json_path)
        if found:
            return found
    if isinstance(data, dict):
        for key in _TOKEN_KEYS:
            if key in data and data[key]:
                return str(data[key])
        # one level deep (e.g. {"data": {"token": ...}})
        for value in data.values():
            if isinstance(value, dict):
                for key in _TOKEN_KEYS:
                    if key in value and value[key]:
                        return str(value[key])
    return None


class JWTAuthenticator:
    def __init__(
        self,
        base_url: str,
        login_endpoint: str,
        token_json_path: Optional[str] = None,
        timeout: float = 15.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.login_endpoint = login_endpoint
        self.token_json_path = token_json_path
        self.client = httpx.AsyncClient(timeout=timeout)

    async def login(self, label: str, email: str, password: str) -> UserSession:
        url = f"{self.base_url}{self.login_endpoint}"
        try:
            resp = await self.client.post(
                url, json={"email": email, "password": password}
            )
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Login request failed for {email}: {exc}") from exc

        if resp.status_code >= 400:
            raise RuntimeError(
                f"Login failed for {email}: HTTP {resp.status_code} — {resp.text[:200]}"
            )

        try:
            data = resp.json()
        except ValueError:
            data = {}

        token = _extract_token(data, self.token_json_path)
        if not token:
            raise RuntimeError(
                f"Could not find token in login response for {email}. "
                f"Response keys: {list(data) if isinstance(data, dict) else type(data)}"
            )
        return UserSession(label=label, email=email, token=token)

    async def close(self) -> None:
        await self.client.aclose()
