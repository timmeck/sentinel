"""Tests for YAML-based check templates."""

import tempfile
from pathlib import Path

import yaml

from src.scanner.template_loader import (
    _check_matchers,
    _get_paths,
    _match_body_contains,
    _match_min_size,
    _match_status,
    load_templates,
)


def test_load_templates_from_default_dir():
    """Built-in templates load successfully."""
    templates = load_templates()
    assert len(templates) >= 8
    ids = [t["id"] for t in templates]
    assert "exposed-env-file" in ids
    assert "exposed-git-config" in ids
    assert "exposed-phpinfo" in ids
    assert "exposed-swagger" in ids
    assert "exposed-backup-files" in ids
    assert "exposed-server-status" in ids
    assert "exposed-actuator" in ids
    assert "exposed-debug-endpoint" in ids


def test_load_templates_from_custom_dir():
    """Templates load from a custom directory."""
    with tempfile.TemporaryDirectory() as d:
        t = Path(d) / "test_check.yaml"
        t.write_text(
            yaml.dump(
                {
                    "id": "test-check",
                    "name": "Test Check",
                    "severity": "low",
                    "cwe": "CWE-000",
                    "request": {"method": "GET", "path": "/test"},
                    "matchers": [{"type": "status", "values": [200]}],
                }
            )
        )
        templates = load_templates(Path(d))
        assert len(templates) == 1
        assert templates[0]["id"] == "test-check"


def test_load_templates_empty_dir():
    """Empty directory returns empty list."""
    with tempfile.TemporaryDirectory() as d:
        assert load_templates(Path(d)) == []


def test_load_templates_missing_dir():
    """Missing directory returns empty list."""
    assert load_templates(Path("/nonexistent/dir")) == []


def test_get_paths_single():
    t = {"request": {"method": "GET", "path": "/.env"}}
    assert _get_paths(t) == ["/.env"]


def test_get_paths_multiple():
    t = {"request": {"method": "GET", "paths": ["/a", "/b", "/c"]}}
    assert _get_paths(t) == ["/a", "/b", "/c"]


def test_get_paths_none():
    t = {"request": {"method": "GET"}}
    assert _get_paths(t) == []


def test_match_status_pass():
    assert _match_status({"values": [200, 301]}, 200) is True


def test_match_status_fail():
    assert _match_status({"values": [200]}, 404) is False


def test_match_body_contains_any():
    m = {"values": ["SECRET", "PASSWORD"], "condition": "any"}
    assert _match_body_contains(m, "my SECRET value") is True
    assert _match_body_contains(m, "nothing here") is False


def test_match_body_contains_all():
    m = {"values": ["SECRET", "PASSWORD"], "condition": "all"}
    assert _match_body_contains(m, "SECRET and PASSWORD") is True
    assert _match_body_contains(m, "only SECRET") is False


def test_match_body_contains_case_insensitive():
    m = {"values": ["DB_PASSWORD"], "condition": "any"}
    assert _match_body_contains(m, "db_password=foo") is True


def test_match_min_size():
    assert _match_min_size({"value": 100}, 150) is True
    assert _match_min_size({"value": 100}, 50) is False
    assert _match_min_size({"value": 100}, 100) is True


def test_check_matchers_all_pass():
    t = {
        "matchers": [
            {"type": "status", "values": [200]},
            {"type": "body_contains", "values": ["SECRET"], "condition": "any"},
        ]
    }
    assert _check_matchers(t, 200, "contains SECRET", 100) is True


def test_check_matchers_status_fails():
    t = {
        "matchers": [
            {"type": "status", "values": [200]},
            {"type": "body_contains", "values": ["SECRET"], "condition": "any"},
        ]
    }
    assert _check_matchers(t, 404, "contains SECRET", 100) is False


def test_check_matchers_body_fails():
    t = {
        "matchers": [
            {"type": "status", "values": [200]},
            {"type": "body_contains", "values": ["SECRET"], "condition": "any"},
        ]
    }
    assert _check_matchers(t, 200, "nothing here", 100) is False


def test_check_matchers_empty():
    assert _check_matchers({"matchers": []}, 200, "body", 100) is False
    assert _check_matchers({}, 200, "body", 100) is False


def test_check_matchers_min_size():
    t = {
        "matchers": [
            {"type": "status", "values": [200]},
            {"type": "min_size", "value": 100},
        ]
    }
    assert _check_matchers(t, 200, "x" * 200, 200) is True
    assert _check_matchers(t, 200, "x", 1) is False


def test_template_structure():
    """All built-in templates have required fields."""
    templates = load_templates()
    for t in templates:
        assert "id" in t, f"Template missing 'id': {t}"
        assert "name" in t, f"Template {t['id']} missing 'name'"
        assert "severity" in t, f"Template {t['id']} missing 'severity'"
        assert "request" in t, f"Template {t['id']} missing 'request'"
        assert "matchers" in t, f"Template {t['id']} missing 'matchers'"
        assert t["severity"] in ("critical", "high", "medium", "low", "info")
        paths = _get_paths(t)
        assert len(paths) > 0, f"Template {t['id']} has no paths"
        for p in paths:
            assert p.startswith("/"), f"Template {t['id']}: path '{p}' must start with /"
