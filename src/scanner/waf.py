"""WAF Detection -- Identify Web Application Firewalls.

Sends test requests and analyzes response headers, body content,
and 403 responses to fingerprint WAF vendors.
"""

import httpx

from src.config import SCAN_TIMEOUT
from src.utils.logger import get_logger

log = get_logger("waf")

WAF_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "body_patterns": ["cloudflare", "cf-browser-verification", "ray ID"],
        "status_403_patterns": ["attention required", "cloudflare"],
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id"],
        "body_patterns": ["aws waf", "request blocked"],
        "status_403_patterns": ["forbidden", "aws"],
    },
    "modsecurity": {
        "headers": ["x-mod-security"],
        "body_patterns": ["mod_security", "modsecurity", "not acceptable"],
        "status_403_patterns": ["modsecurity"],
    },
    "akamai": {
        "headers": ["x-akamai-transformed", "akamai-grn"],
        "body_patterns": ["akamai", "access denied"],
        "status_403_patterns": ["reference #"],
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body_patterns": ["sucuri", "cloudproxy"],
        "status_403_patterns": ["sucuri"],
    },
}

# Payloads designed to trigger WAF responses
WAF_TRIGGER_PATHS = [
    "/<script>alert(1)</script>",
    "/?id=1' OR '1'='1",
    "/etc/passwd",
    "/?cmd=cat+/etc/passwd",
]


async def detect_waf(url: str) -> list[dict]:
    """Detect WAF by analyzing headers/body from normal and trigger requests.

    Returns list of detected WAFs with confidence info.
    """
    detected = {}

    async with httpx.AsyncClient(timeout=SCAN_TIMEOUT, follow_redirects=True, verify=False) as client:
        # Phase 1: Normal request — check headers for WAF fingerprints
        try:
            resp = await client.get(url)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            body_lower = resp.text[:50000].lower()

            for waf_name, sigs in WAF_SIGNATURES.items():
                score = 0
                evidence = []

                # Check headers
                for hdr in sigs["headers"]:
                    if hdr.lower() in headers_lower:
                        score += 2
                        evidence.append(f"header '{hdr}' present")

                # Check body patterns
                for pattern in sigs["body_patterns"]:
                    if pattern.lower() in body_lower:
                        score += 1
                        evidence.append(f"body contains '{pattern}'")

                if score > 0:
                    detected[waf_name] = {"score": score, "evidence": evidence}

        except (httpx.HTTPError, TimeoutError, OSError) as e:
            log.debug(f"WAF normal request failed: {e}")

        # Phase 2: Trigger requests — try to provoke WAF blocks
        for path in WAF_TRIGGER_PATHS:
            try:
                trigger_url = url.rstrip("/") + path
                resp = await client.get(trigger_url)
                body_lower = resp.text[:50000].lower()

                for waf_name, sigs in WAF_SIGNATURES.items():
                    score = detected.get(waf_name, {}).get("score", 0)
                    evidence = detected.get(waf_name, {}).get("evidence", [])

                    if resp.status_code == 403:
                        for pattern in sigs["status_403_patterns"]:
                            if pattern.lower() in body_lower:
                                score += 3
                                evidence.append(f"403 body matches '{pattern}' on {path}")

                    # Also check body patterns on trigger responses
                    for pattern in sigs["body_patterns"]:
                        if pattern.lower() in body_lower and f"body contains '{pattern}'" not in evidence:
                            score += 1
                            evidence.append(f"trigger body contains '{pattern}'")

                    if score > 0:
                        detected[waf_name] = {"score": score, "evidence": evidence}

            except (httpx.HTTPError, TimeoutError, OSError) as e:
                log.debug(f"WAF trigger request failed for {path}: {e}")

    return [
        {"name": name, "confidence": min(info["score"] / 5.0, 1.0), "evidence": info["evidence"]}
        for name, info in detected.items()
        if info["score"] >= 1
    ]


async def check_waf(url: str) -> list[dict]:
    """Run WAF detection and return findings for the scan pipeline."""
    findings = []

    try:
        wafs = await detect_waf(url)

        if wafs:
            for waf in wafs:
                confidence_pct = int(waf["confidence"] * 100)
                findings.append(
                    {
                        "severity": "info",
                        "category": "waf",
                        "title": f"WAF detected: {waf['name']} ({confidence_pct}% confidence)",
                        "description": (
                            f"Web Application Firewall '{waf['name']}' detected with {confidence_pct}% confidence. "
                            f"WAFs can mask vulnerabilities and block scanning. Results may be incomplete."
                        ),
                        "evidence": "; ".join(waf["evidence"]),
                        "recommendation": "WAF presence noted. Manual testing may be needed to bypass WAF protections.",
                        "cwe_id": None,
                    }
                )
        else:
            findings.append(
                {
                    "severity": "info",
                    "category": "waf",
                    "title": "No WAF detected",
                    "description": "No Web Application Firewall was detected. The target may be unprotected against common attacks.",
                    "evidence": "No WAF signatures matched in headers or response body.",
                    "recommendation": "Consider deploying a WAF to protect against common web attacks (OWASP Top 10).",
                    "cwe_id": "CWE-693",
                }
            )

    except (OSError, TimeoutError, RuntimeError, ValueError) as e:
        log.warning(f"WAF detection failed for {url}: {e}")

    return findings
