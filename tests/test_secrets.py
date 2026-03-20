"""Tests for secret scanner in crawler module."""

import re

from src.scanner.crawler import SECRET_PATTERNS, scan_secrets


def test_secret_patterns_compile():
    """All secret patterns are valid regex."""
    for name, pattern in SECRET_PATTERNS.items():
        try:
            re.compile(pattern)
        except re.error as e:
            raise AssertionError(f"Pattern '{name}' is invalid regex: {e}")


def test_detect_aws_key():
    content = "config = { key: 'AKIAIOSFODNN7EXAMPLE' }"
    findings = scan_secrets(content, "https://example.com/config.js")
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["category"] == "secrets"
    assert "CWE-798" == findings[0]["cwe_id"]


def test_detect_github_token():
    content = 'const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12";'
    findings = scan_secrets(content, "https://example.com/app.js")
    assert len(findings) == 1
    assert "github" in findings[0]["title"].lower()


def test_detect_stripe_key():
    content = 'stripe.key = "' + 'sk' + '_live_' + 'T' * 24 + '";'
    findings = scan_secrets(content, "https://example.com")
    assert len(findings) == 1
    assert "stripe" in findings[0]["title"].lower()


def test_detect_jwt():
    content = 'token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"'
    findings = scan_secrets(content, "https://example.com")
    assert len(findings) == 1
    assert "jwt" in findings[0]["title"].lower()


def test_detect_private_key():
    content = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
    findings = scan_secrets(content, "https://example.com")
    assert len(findings) == 1
    assert "private" in findings[0]["title"].lower()
    assert findings[0]["cwe_id"] == "CWE-321"


def test_detect_slack_token():
    content = 'slack_token = "xoxb-1234567890-abcdefghij"'
    findings = scan_secrets(content, "https://example.com")
    assert len(findings) == 1
    assert "slack" in findings[0]["title"].lower()


def test_detect_google_api_key():
    content = 'key = "AIzaSyA1234567890abcdefghijklmnopqrstuvw"'
    findings = scan_secrets(content, "https://example.com")
    assert any("google" in f["title"].lower() for f in findings)


def test_detect_generic_api_key():
    content = 'api_key = "abcdefghijklmnopqrstuvwxyz1234"'
    findings = scan_secrets(content, "https://example.com")
    assert len(findings) == 1
    assert "api key" in findings[0]["title"].lower()


def test_no_false_positive_on_clean_content():
    content = "<html><body><h1>Welcome</h1><p>Nothing secret here.</p></body></html>"
    findings = scan_secrets(content, "https://example.com")
    assert len(findings) == 0


def test_deduplication():
    content = 'key1 = "AKIAIOSFODNN7EXAMPLE"\nkey2 = "AKIAIOSFODNN7EXAMPLE"'
    findings = scan_secrets(content, "https://example.com")
    assert len(findings) == 1


def test_multiple_secrets():
    content = (
        'aws = "AKIAIOSFODNN7EXAMPLE"\n'
        'stripe = "' + 'sk' + '_live_' + 'T' * 24 + '"\n'
    )
    findings = scan_secrets(content, "https://example.com")
    assert len(findings) == 2


def test_scan_secrets_includes_source_url():
    content = 'const key = "AKIAIOSFODNN7EXAMPLE";'
    findings = scan_secrets(content, "https://example.com/app.js")
    assert "example.com/app.js" in findings[0]["evidence"]
