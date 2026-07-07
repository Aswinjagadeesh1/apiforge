"""Core data models shared across APIForge modules."""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4,
        }
        return order[self.value]


class Endpoint(BaseModel):
    """A single API endpoint extracted from a Postman collection."""

    name: str
    method: str
    raw_url: str  # original, may contain {{vars}}
    path: str  # resolved path portion, e.g. /identity/api/v2/user/dashboard
    query: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[Any] = None  # parsed JSON body if present

    def numeric_ids(self) -> list[str]:
        """Return numeric path segments (candidate object IDs for BOLA)."""
        import re

        return re.findall(r"/(\d+)(?=/|$)", self.path)


class UserSession(BaseModel):
    """An authenticated user session."""

    label: str  # "user_a" / "user_b"
    email: str
    token: Optional[str] = None

    @property
    def authenticated(self) -> bool:
        return bool(self.token)


class Finding(BaseModel):
    """A single vulnerability finding, shaped for a pentest report."""

    check_id: str
    title: str
    severity: Severity
    owasp_category: str
    cwe: str
    cvss_score: float
    method: str
    endpoint: str
    description: str
    poc_request: str
    poc_response: str
    remediation: str
