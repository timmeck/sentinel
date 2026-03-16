"""Tests for API check modules."""

from src.scanner.api_checks import API_PATHS, GRAPHQL_INTROSPECTION
import json


def test_api_paths_format():
    for path in API_PATHS:
        assert path.startswith("/"), f"Path {path} should start with /"


def test_graphql_introspection_valid_json():
    data = json.loads(GRAPHQL_INTROSPECTION)
    assert "query" in data
    assert "__schema" in data["query"]
