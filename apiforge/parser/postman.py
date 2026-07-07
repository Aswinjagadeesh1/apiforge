"""Postman Collection v2.1 parser.

Walks a Postman collection (including nested folders), resolves {{variables}}
from collection-level variables and an optional environment file, and produces
a flat list of Endpoint objects the rest of APIForge can consume.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

from apiforge.models import Endpoint

_VAR_PATTERN = re.compile(r"\{\{([^}]+)\}\}")


class PostmanParser:
    def __init__(
        self,
        collection_path: str | Path,
        environment_path: Optional[str | Path] = None,
        extra_vars: Optional[dict[str, str]] = None,
    ) -> None:
        self.collection_path = Path(collection_path)
        with open(self.collection_path, encoding="utf-8") as f:
            self.collection: dict[str, Any] = json.load(f)
# Some Postman exports wrap everything in a "collection" key.
        if "collection" in self.collection and "item" not in self.collection:
            self.collection = self.collection["collection"]
        self.variables: dict[str, str] = {}
        self._load_collection_variables()
        if environment_path:
            self._load_environment(Path(environment_path))
        if extra_vars:
            self.variables.update(extra_vars)

        self.endpoints: list[Endpoint] = []

    # ---------- variable loading ----------
    def _load_collection_variables(self) -> None:
        for var in self.collection.get("variable", []):
            key = var.get("key")
            if key is not None:
                self.variables[key] = str(var.get("value", ""))

    def _load_environment(self, path: Path) -> None:
        with open(path, encoding="utf-8") as f:
            env = json.load(f)
        # Postman environment export format: {"values": [{"key":..,"value":..}]}
        for var in env.get("values", env.get("variable", [])):
            if var.get("enabled", True) is False:
                continue
            key = var.get("key")
            if key is not None:
                self.variables[key] = str(var.get("value", ""))

    def resolve(self, text: str) -> str:
        """Replace {{var}} occurrences, leaving unknown vars untouched."""
        if not text:
            return text
        # Resolve iteratively so nested variables (a var that expands to
        # another {{var}}) also get resolved, capped to avoid infinite loops.
        for _ in range(5):
            new = _VAR_PATTERN.sub(
                lambda m: self.variables.get(m.group(1).strip(), m.group(0)), text
            )
            if new == text:
                break
            text = new
        return text

    # ---------- walking ----------
    def parse(self) -> list[Endpoint]:
        self._walk(self.collection.get("item", []))
        return self.endpoints

    def _walk(self, items: list[dict[str, Any]]) -> None:
        for item in items:
            if "item" in item:  # folder
                self._walk(item["item"])
            elif "request" in item:
                ep = self._parse_request(item)
                if ep:
                    self.endpoints.append(ep)

    def _parse_request(self, item: dict[str, Any]) -> Optional[Endpoint]:
        req = item["request"]
        if isinstance(req, str):
            return None  # bare URL string, no method info

        method = req.get("method", "GET").upper()

        # URL can be a string or an object with raw/host/path
        url_field = req.get("url", "")
        if isinstance(url_field, dict):
            raw_url = url_field.get("raw", "")
        else:
            raw_url = url_field
        raw_url = self.resolve(raw_url)

        parts = urlsplit(raw_url)
        path = parts.path or "/"
        query = dict(
            kv.split("=", 1) if "=" in kv else (kv, "")
            for kv in parts.query.split("&")
            if kv
        )

        headers = {}
        for h in req.get("header", []):
            if h.get("disabled"):
                continue
            key = h.get("key")
            if key:
                headers[key] = self.resolve(str(h.get("value", "")))

        body = self._parse_body(req.get("body"))

        return Endpoint(
            name=item.get("name", "unnamed"),
            method=method,
            raw_url=raw_url,
            path=path,
            query=query,
            headers=headers,
            body=body,
        )

    def _parse_body(self, body: Optional[dict[str, Any]]) -> Optional[Any]:
        if not body:
            return None
        mode = body.get("mode")
        if mode == "raw":
            raw = self.resolve(body.get("raw", ""))
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                return None
        if mode == "urlencoded":
            return {
                p["key"]: self.resolve(str(p.get("value", "")))
                for p in body.get("urlencoded", [])
                if not p.get("disabled") and p.get("key")
            }
        return None
