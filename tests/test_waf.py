"""Tests for WAF detection module."""

from src.scanner.waf import WAF_SIGNATURES, WAF_TRIGGER_PATHS


def test_waf_signatures_structure():
    """All WAF signatures have required fields."""
    for waf_name, sigs in WAF_SIGNATURES.items():
        assert "headers" in sigs, f"{waf_name} missing 'headers'"
        assert "body_patterns" in sigs, f"{waf_name} missing 'body_patterns'"
        assert "status_403_patterns" in sigs, f"{waf_name} missing 'status_403_patterns'"
        assert isinstance(sigs["headers"], list)
        assert isinstance(sigs["body_patterns"], list)
        assert isinstance(sigs["status_403_patterns"], list)
        assert len(sigs["headers"]) > 0, f"{waf_name} has no headers"


def test_waf_signatures_all_lowercase_headers():
    """WAF header signatures should be lowercase for matching."""
    for waf_name, sigs in WAF_SIGNATURES.items():
        for hdr in sigs["headers"]:
            assert hdr == hdr.lower(), f"{waf_name} header '{hdr}' not lowercase"


def test_known_waf_vendors():
    """Known WAF vendors are covered."""
    assert "cloudflare" in WAF_SIGNATURES
    assert "aws_waf" in WAF_SIGNATURES
    assert "modsecurity" in WAF_SIGNATURES
    assert "akamai" in WAF_SIGNATURES
    assert "sucuri" in WAF_SIGNATURES


def test_trigger_paths_format():
    """WAF trigger paths start with /."""
    for path in WAF_TRIGGER_PATHS:
        assert path.startswith("/"), f"Trigger path '{path}' should start with /"


def test_waf_in_scan_modules():
    """WAF check is registered in scan modules."""
    from src.scanner.engine import SCAN_MODULES, SCAN_PROFILES

    assert "waf" in SCAN_MODULES
    assert "waf" in SCAN_PROFILES["full"]
    assert "waf" in SCAN_PROFILES["recon"]
