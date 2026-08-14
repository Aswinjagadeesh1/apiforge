"""OpenAPI / Swagger (2.0 and 3.x) parser.

Produces the same Endpoint objects as the Postman parser, so every check works
unchanged. Handles both Swagger 2.0 ("swagger": "2.0") and OpenAPI 3.x
("openapi": "3.x") path/operation structures.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from apiforge.models import Endpoint


def _load_spec_dict(path_or_url: str):
    """Load an OpenAPI/Swagger spec from a file path or http(s) URL,
    parsing JSON or YAML transparently."""
    import json as _json
    text = None
    if path_or_url.startswith(("http://", "https://")):
        import httpx
        text = httpx.get(path_or_url, timeout=15.0, verify=False).text
    else:
        with open(path_or_url, encoding="utf-8") as f:
            text = f.read()
    # try JSON first, then YAML
    try:
        return _json.loads(text)
    except Exception:
        try:
            import yaml  # pyyaml
        except ImportError as exc:
            raise RuntimeError(
                "Spec is not JSON and PyYAML is not installed. "
                "Run: pip install pyyaml"
            ) from exc
        return yaml.safe_load(text)


_METHODS = ("get", "post", "put", "patch", "delete")


class OpenAPIParser:
    def __init__(
        self,
        spec_path: str | Path,
        extra_vars: Optional[dict[str, str]] = None,
    ) -> None:
        self.spec_path = Path(spec_path)
        self.spec: dict[str, Any] = _load_spec_dict(str(spec_path))
        self.extra_vars = extra_vars or {}
        self.endpoints: list[Endpoint] = []

    def _base_path(self) -> str:
        # Swagger 2.0 uses basePath; OpenAPI 3 uses servers[].url path.
        if "basePath" in self.spec:
            return str(self.spec["basePath"]).rstrip("/")
        servers = self.spec.get("servers", [])
        if servers:
            url = servers[0].get("url", "")
            # keep only the path portion if a full URL is given
            from urllib.parse import urlsplit
            return urlsplit(url).path.rstrip("/")
        return ""

    def _example_body(self, operation: dict[str, Any]) -> Optional[Any]:
        """Build a minimal example body from parameters/requestBody schema."""
        # Swagger 2.0: body parameter with schema
        for p in operation.get("parameters", []):
            if p.get("in") == "body" and "schema" in p:
                return self._schema_example(p["schema"])
        # OpenAPI 3: requestBody.content[app/json].schema
        rb = operation.get("requestBody", {})
        content = rb.get("content", {}) if isinstance(rb, dict) else {}
        for ctype, media in content.items():
            if "json" in ctype and "schema" in media:
                return self._schema_example(media["schema"])
        return None

    def _schema_example(self, schema: dict[str, Any]) -> Any:
        """Very small example generator from a JSON schema object."""
        if not isinstance(schema, dict):
            return {}
        if "example" in schema:
            return schema["example"]
        t = schema.get("type")
        if t == "object" or "properties" in schema:
            out = {}
            for name, prop in schema.get("properties", {}).items():
                out[name] = self._schema_example(prop) if isinstance(prop, dict) else "x"
            return out
        if t == "array":
            return []
        if t == "integer" or t == "number":
            return 1
        if t == "boolean":
            return True
        return "test"

    def parse(self) -> list[Endpoint]:
        base = self._base_path()
        paths = self.spec.get("paths", {})
        for raw_path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method in _METHODS:
                if method not in path_item:
                    continue
                op = path_item[method]
                if not isinstance(op, dict):
                    continue
                full_path = f"{base}{raw_path}"
                body = self._example_body(op)
                self.endpoints.append(
                    Endpoint(
                        name=op.get("operationId", op.get("summary", raw_path)),
                        method=method.upper(),
                        raw_url=full_path,
                        path=full_path,
                        query={},
                        headers={},
                        body=body,
                    )
                )
        return self.endpoints
