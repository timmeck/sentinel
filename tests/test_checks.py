"""Tests for security check modules."""

import asyncio
import pytest
from src.scanner.checks import (
    SECURITY_HEADERS, COMMON_PORTS, SENSITIVE_PATHS, RISKY_PORTS,
    DANGEROUS_HEADERS,
)


def test_security_headers_defined():
    """All security headers have required fields."""
    for header, info in SECURITY_HEADERS.items():
        assert "severity" in info
        assert "title" in info
        assert "desc" in info
        assert "rec" in info
        assert "cwe" in info


def test_common_ports_defined():
    """Common ports have service names."""
    assert 80 in COMMON_PORTS
    assert 443 in COMMON_PORTS
    assert 22 in COMMON_PORTS
    assert COMMON_PORTS[80] == "HTTP"
    assert COMMON_PORTS[443] == "HTTPS"


def test_risky_ports_subset():
    """Risky ports are a subset of common ports."""
    for port in RISKY_PORTS:
        assert port in COMMON_PORTS, f"Risky port {port} not in COMMON_PORTS"


def test_sensitive_paths_format():
    """All sensitive paths start with /."""
    for path in SENSITIVE_PATHS:
        assert path.startswith("/"), f"Path {path} should start with /"


def test_dangerous_headers_format():
    """Dangerous headers have correct tuple format."""
    for header, (sev, desc, rec) in DANGEROUS_HEADERS.items():
        assert sev in ("info", "low", "medium", "high", "critical")
        assert len(desc) > 0
        assert len(rec) > 0
