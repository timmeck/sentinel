"""Tests for vulnerability check modules."""

from src.scanner.vulns import (
    REDIRECT_PARAMS,
    SQLI_ERROR_PATTERNS,
    SQLI_PAYLOADS,
    TRAVERSAL_INDICATORS,
    TRAVERSAL_PAYLOADS,
    XSS_PAYLOADS,
)


def test_sqli_payloads_defined():
    assert len(SQLI_PAYLOADS) >= 3
    for payload, desc in SQLI_PAYLOADS:
        assert len(payload) > 0
        assert len(desc) > 0


def test_sqli_error_patterns_are_regex():
    import re

    for pattern in SQLI_ERROR_PATTERNS:
        re.compile(pattern, re.IGNORECASE)  # Should not raise


def test_xss_payloads_contain_markers():
    for payload, desc in XSS_PAYLOADS:
        assert len(payload) > 0
        assert any(kw in payload.lower() for kw in ["script", "onerror", "onload", "javascript"])


def test_redirect_params_common():
    assert "redirect" in REDIRECT_PARAMS
    assert "next" in REDIRECT_PARAMS
    assert "url" in REDIRECT_PARAMS


def test_traversal_payloads():
    for payload, desc in TRAVERSAL_PAYLOADS:
        assert ".." in payload
        assert len(desc) > 0


def test_traversal_indicators():
    assert "root:x:" in TRAVERSAL_INDICATORS
    assert any("fonts" in i.lower() or "extensions" in i.lower() for i in TRAVERSAL_INDICATORS)
