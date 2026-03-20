"""Tests for API fuzzer module."""

from src.scanner.api_fuzzer import (
    FUZZ_METHODS,
    SPEC_PATHS,
    TRAVERSAL_INDICATORS,
    TRAVERSAL_PAYLOADS,
    _extract_endpoints,
)


def test_spec_paths_format():
    """All spec paths start with /."""
    for path in SPEC_PATHS:
        assert path.startswith("/"), f"Spec path should start with /: {path}"


def test_fuzz_methods():
    """Fuzz methods are valid HTTP methods."""
    for m in FUZZ_METHODS:
        assert m in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD")


def test_traversal_payloads_not_empty():
    assert len(TRAVERSAL_PAYLOADS) > 0


def test_traversal_indicators_not_empty():
    assert len(TRAVERSAL_INDICATORS) > 0


def test_extract_endpoints_basic():
    """Extract endpoints from a basic OpenAPI spec."""
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/api/users": {
                "get": {"summary": "List users"},
                "post": {"summary": "Create user"},
            },
            "/api/users/{id}": {
                "get": {
                    "summary": "Get user",
                    "parameters": [
                        {"name": "id", "in": "path", "required": True}
                    ],
                },
                "delete": {"summary": "Delete user"},
            },
        },
    }
    endpoints = _extract_endpoints(spec)
    assert len(endpoints) == 2

    users_ep = next(ep for ep in endpoints if ep["path"] == "/api/users")
    assert "GET" in users_ep["methods"]
    assert "POST" in users_ep["methods"]

    user_ep = next(ep for ep in endpoints if ep["path"] == "/api/users/{id}")
    assert "GET" in user_ep["methods"]
    assert "DELETE" in user_ep["methods"]
    assert len(user_ep["parameters"]) == 1
    assert user_ep["parameters"][0]["name"] == "id"
    assert user_ep["parameters"][0]["in"] == "path"


def test_extract_endpoints_empty_spec():
    """Empty spec returns empty list."""
    assert _extract_endpoints({}) == []
    assert _extract_endpoints({"paths": {}}) == []


def test_extract_endpoints_with_query_params():
    """Extract query parameters from spec."""
    spec = {
        "paths": {
            "/api/search": {
                "get": {
                    "parameters": [
                        {"name": "q", "in": "query", "required": True},
                        {"name": "file", "in": "query", "required": False},
                    ]
                }
            }
        }
    }
    endpoints = _extract_endpoints(spec)
    assert len(endpoints) == 1
    assert len(endpoints[0]["parameters"]) == 2
    names = [p["name"] for p in endpoints[0]["parameters"]]
    assert "q" in names
    assert "file" in names


def test_extract_endpoints_path_level_params():
    """Path-level parameters are extracted."""
    spec = {
        "paths": {
            "/api/items/{itemId}": {
                "parameters": [{"name": "itemId", "in": "path", "required": True}],
                "get": {"summary": "Get item"},
            }
        }
    }
    endpoints = _extract_endpoints(spec)
    assert len(endpoints) == 1
    assert len(endpoints[0]["parameters"]) == 1
    assert endpoints[0]["parameters"][0]["name"] == "itemId"


def test_extract_endpoints_ignores_invalid():
    """Invalid path items are skipped."""
    spec = {
        "paths": {
            "/valid": {"get": {"summary": "OK"}},
            "/invalid": "not a dict",
        }
    }
    endpoints = _extract_endpoints(spec)
    assert len(endpoints) == 1
    assert endpoints[0]["path"] == "/valid"
