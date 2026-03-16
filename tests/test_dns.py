"""Tests for DNS check modules."""

from src.scanner.dns_checks import COMMON_SUBDOMAINS, _get_base_domain


def test_common_subdomains():
    assert "www" in COMMON_SUBDOMAINS
    assert "admin" in COMMON_SUBDOMAINS
    assert "api" in COMMON_SUBDOMAINS
    assert "staging" in COMMON_SUBDOMAINS
    assert len(COMMON_SUBDOMAINS) >= 30


def test_get_base_domain():
    assert _get_base_domain("www.example.com") == "example.com"
    assert _get_base_domain("sub.domain.example.com") == "example.com"
    assert _get_base_domain("example.com") == "example.com"
    assert _get_base_domain("localhost") == "localhost"
