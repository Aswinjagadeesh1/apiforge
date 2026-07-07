"""Unit tests for the Postman parser and core models."""
import json
from pathlib import Path

from apiforge.models import Endpoint, Severity
from apiforge.parser.postman import PostmanParser

SAMPLES = Path(__file__).parent.parent / "samples"


def test_parser_extracts_all_endpoints():
    parser = PostmanParser(SAMPLES / "vulnshop.postman.json")
    endpoints = parser.parse()
    assert len(endpoints) == 6
    methods = {e.method for e in endpoints}
    assert "GET" in methods and "POST" in methods and "PUT" in methods


def test_parser_resolves_base_url_variable():
    parser = PostmanParser(SAMPLES / "vulnshop.postman.json")
    endpoints = parser.parse()
    # {{baseUrl}} should be gone from the resolved raw_url
    assert all("{{" not in e.raw_url for e in endpoints)
    assert any(e.path == "/api/orders/1001" for e in endpoints)


def test_parser_parses_json_body():
    parser = PostmanParser(SAMPLES / "vulnshop.postman.json")
    endpoints = parser.parse()
    put = next(e for e in endpoints if e.method == "PUT")
    assert isinstance(put.body, dict)
    assert put.body.get("name") == "Alice"


def test_endpoint_numeric_ids():
    ep = Endpoint(name="x", method="GET", raw_url="", path="/api/orders/1001")
    assert ep.numeric_ids() == ["1001"]
    ep2 = Endpoint(name="x", method="GET", raw_url="", path="/api/users/me")
    assert ep2.numeric_ids() == []


def test_severity_ordering():
    assert Severity.CRITICAL.rank < Severity.HIGH.rank < Severity.MEDIUM.rank
