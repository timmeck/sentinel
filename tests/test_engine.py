"""Tests for scan engine."""

import asyncio
import pytest
from src.scanner.engine import ScanEngine, SCAN_PROFILES, SCAN_MODULES


def test_scan_profiles_valid():
    """All scan profiles reference valid modules."""
    for profile, checks in SCAN_PROFILES.items():
        for check in checks:
            assert check in SCAN_MODULES, f"Profile '{profile}' references unknown module '{check}'"


def test_scan_modules_have_functions():
    """All scan modules have name and callable function."""
    for name, (display_name, fn) in SCAN_MODULES.items():
        assert len(display_name) > 0
        assert callable(fn)


def test_calculate_score():
    """Score calculation works correctly."""
    from src.db.database import Database
    engine = ScanEngine.__new__(ScanEngine)

    # No findings = perfect score
    assert engine._calculate_score([]) == 100.0

    # One critical = 75
    assert engine._calculate_score([{"severity": "critical"}]) == 75.0

    # One high = 85
    assert engine._calculate_score([{"severity": "high"}]) == 85.0

    # One medium = 95
    assert engine._calculate_score([{"severity": "medium"}]) == 95.0

    # One low = 98
    assert engine._calculate_score([{"severity": "low"}]) == 98.0

    # Info doesn't affect score
    assert engine._calculate_score([{"severity": "info"}]) == 100.0

    # Multiple findings
    findings = [
        {"severity": "critical"},  # -25
        {"severity": "high"},      # -15
        {"severity": "medium"},    # -5
    ]
    assert engine._calculate_score(findings) == 55.0

    # Score can't go below 0
    findings = [{"severity": "critical"}] * 10
    assert engine._calculate_score(findings) == 0.0


def test_fallback_report():
    """Fallback report generates valid markdown."""
    engine = ScanEngine.__new__(ScanEngine)
    findings = [
        {"severity": "high", "title": "Missing HSTS", "description": "No HSTS", "recommendation": "Add HSTS"},
        {"severity": "info", "title": "Server header", "description": "nginx/1.24"},
    ]
    report = engine._fallback_report("https://example.com", findings, 85.0)
    assert "example.com" in report
    assert "85" in report
    assert "Missing HSTS" in report
    assert "HIGH" in report
