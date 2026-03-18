"""Active Vulnerability Testing -- Safe probing for common web vulnerabilities.

Tests for OWASP Top 10 issues using detection payloads (not exploitation):
- SQL Injection (error-based detection)
- Cross-Site Scripting (reflected XSS detection)
- Open Redirect
- Server-Side Request Forgery indicators
- Directory Traversal
- Command Injection indicators
"""

import asyncio
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from src.config import SCAN_TIMEOUT
from src.utils.logger import get_logger

log = get_logger("vulns")

# SQL injection detection payloads (error-based, safe)
SQLI_PAYLOADS = [
    ("'", "single quote"),
    ("1' OR '1'='1", "boolean tautology"),
    ("1; SELECT 1--", "stacked query"),
    ("' UNION SELECT NULL--", "union select"),
]

SQLI_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"unclosed quotation mark",
    r"Microsoft OLE DB Provider for SQL Server",
    r"PostgreSQL.*ERROR",
    r"sqlite3\.OperationalError",
    r"SQLSTATE\[",
    r"Syntax error.*in query expression",
    r"pg_query\(\)",
    r"ORA-\d{5}",
    r"SQLite3::query",
    r"System\.Data\.SqlClient",
]

# XSS detection payloads (harmless, detectable)
XSS_PAYLOADS = [
    ('<script>alert("XSS")</script>', "script tag"),
    ('"><img src=x onerror=alert(1)>', "img onerror"),
    ("javascript:alert(1)", "javascript URI"),
    ("'><svg/onload=alert(1)>", "svg onload"),
]

# Open redirect payloads
REDIRECT_PARAMS = [
    "url",
    "redirect",
    "next",
    "return",
    "returnUrl",
    "redirect_uri",
    "continue",
    "dest",
    "destination",
    "go",
    "target",
    "rurl",
    "return_url",
]
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
]

# Directory traversal payloads
TRAVERSAL_PAYLOADS = [
    ("../../../etc/passwd", "Linux passwd"),
    ("..\\..\\..\\windows\\win.ini", "Windows win.ini"),
    ("....//....//....//etc/passwd", "double-encoded"),
]

TRAVERSAL_INDICATORS = [
    "root:x:",
    "root:*:",
    "[fonts]",
    "[extensions]",
    "daemon:",
    "/bin/bash",
    "/bin/sh",
]


async def check_sqli(url: str) -> list[dict]:
    """Test URL parameters for SQL injection vulnerabilities."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return findings

    async with httpx.AsyncClient(timeout=SCAN_TIMEOUT, follow_redirects=True, verify=False) as client:
        # Get baseline response
        try:
            await client.get(url)
        except (httpx.HTTPError, TimeoutError, OSError):
            return findings

        for param_name in params:
            for payload, payload_type in SQLI_PAYLOADS:
                test_params = {k: v[0] if v else "" for k, v in params.items()}
                test_params[param_name] = payload

                test_parsed = parsed._replace(query=urlencode(test_params))
                test_url = urlunparse(test_parsed)

                try:
                    resp = await client.get(test_url)
                    body = resp.text

                    # Check for SQL error patterns
                    for pattern in SQLI_ERROR_PATTERNS:
                        if re.search(pattern, body, re.IGNORECASE):
                            findings.append(
                                {
                                    "severity": "critical",
                                    "category": "sqli",
                                    "title": f"Potential SQL Injection in '{param_name}' parameter",
                                    "description": f"SQL error detected when injecting {payload_type} payload into parameter '{param_name}'. Database error message visible in response.",
                                    "evidence": f"Payload: {payload}, Pattern matched: {pattern}, URL: {test_url[:200]}",
                                    "recommendation": f"Use parameterized queries/prepared statements for parameter '{param_name}'. Never concatenate user input into SQL.",
                                    "cwe_id": "CWE-89",
                                    "cvss_score": 9.8,
                                }
                            )
                            break  # One finding per param is enough
                except (httpx.HTTPError, TimeoutError, OSError):
                    continue

    return findings


async def check_xss(url: str) -> list[dict]:
    """Test URL parameters for reflected XSS."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return findings

    async with httpx.AsyncClient(timeout=SCAN_TIMEOUT, follow_redirects=True, verify=False) as client:
        for param_name in params:
            for payload, payload_type in XSS_PAYLOADS:
                test_params = {k: v[0] if v else "" for k, v in params.items()}
                test_params[param_name] = payload

                test_parsed = parsed._replace(query=urlencode(test_params))
                test_url = urlunparse(test_parsed)

                try:
                    resp = await client.get(test_url)
                    # Check if payload is reflected unescaped
                    if payload in resp.text:
                        findings.append(
                            {
                                "severity": "high",
                                "category": "xss",
                                "title": f"Reflected XSS in '{param_name}' parameter",
                                "description": f"Payload ({payload_type}) reflected unescaped in response for parameter '{param_name}'.",
                                "evidence": f"Payload: {payload}, reflected in response body. URL: {test_url[:200]}",
                                "recommendation": f"Sanitize/escape output for parameter '{param_name}'. Implement Content-Security-Policy.",
                                "cwe_id": "CWE-79",
                                "cvss_score": 6.1,
                            }
                        )
                        break  # One per param
                except (httpx.HTTPError, TimeoutError, OSError):
                    continue

    return findings


async def check_open_redirect(url: str) -> list[dict]:
    """Test for open redirect vulnerabilities."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    async with httpx.AsyncClient(timeout=SCAN_TIMEOUT, follow_redirects=False, verify=False) as client:
        for param in REDIRECT_PARAMS:
            for payload in REDIRECT_PAYLOADS:
                test_url = f"{base}/?{param}={payload}"
                try:
                    resp = await client.get(test_url)
                    location = resp.headers.get("location", "")
                    if resp.status_code in (301, 302, 307, 308):
                        if "evil.com" in location:
                            findings.append(
                                {
                                    "severity": "medium",
                                    "category": "redirect",
                                    "title": f"Open redirect via '{param}' parameter",
                                    "description": f"Server redirects to attacker-controlled URL when '{param}' parameter contains external URL.",
                                    "evidence": f"GET {test_url} -> {resp.status_code} Location: {location}",
                                    "recommendation": "Validate redirect targets against a whitelist. Never redirect to user-supplied URLs.",
                                    "cwe_id": "CWE-601",
                                    "cvss_score": 6.1,
                                }
                            )
                            break  # One per param
                except (httpx.HTTPError, TimeoutError, OSError):
                    continue

    return findings


async def check_directory_traversal(url: str) -> list[dict]:
    """Test for directory traversal/path traversal."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Test URL parameters
    file_params = [
        p
        for p in params
        if any(kw in p.lower() for kw in ["file", "path", "page", "doc", "template", "include", "dir", "folder"])
    ]

    if not file_params:
        return findings

    async with httpx.AsyncClient(timeout=SCAN_TIMEOUT, follow_redirects=True, verify=False) as client:
        for param_name in file_params:
            for payload, payload_type in TRAVERSAL_PAYLOADS:
                test_params = {k: v[0] if v else "" for k, v in params.items()}
                test_params[param_name] = payload

                test_parsed = parsed._replace(query=urlencode(test_params))
                test_url = urlunparse(test_parsed)

                try:
                    resp = await client.get(test_url)
                    for indicator in TRAVERSAL_INDICATORS:
                        if indicator in resp.text:
                            findings.append(
                                {
                                    "severity": "critical",
                                    "category": "traversal",
                                    "title": f"Directory traversal in '{param_name}' parameter",
                                    "description": f"Path traversal payload ({payload_type}) exposed system files via parameter '{param_name}'.",
                                    "evidence": f"Payload: {payload}, Indicator: {indicator} found in response",
                                    "recommendation": "Validate file paths against a whitelist. Use chroot or sandbox for file access.",
                                    "cwe_id": "CWE-22",
                                    "cvss_score": 9.1,
                                }
                            )
                            break
                except (httpx.HTTPError, TimeoutError, OSError):
                    continue

    return findings


async def check_rate_limiting(url: str) -> list[dict]:
    """Check if the target has rate limiting on sensitive endpoints."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Endpoints that should have rate limiting
    sensitive_endpoints = ["/login", "/api/login", "/auth", "/register", "/api/auth", "/reset-password"]

    async with httpx.AsyncClient(timeout=SCAN_TIMEOUT, follow_redirects=True, verify=False) as client:
        for endpoint in sensitive_endpoints:
            test_url = f"{base}{endpoint}"
            success_count = 0

            try:
                # Send rapid requests
                tasks = [client.post(test_url, data={"username": "test", "password": "test"}) for _ in range(10)]
                responses = await asyncio.gather(*tasks, return_exceptions=True)

                for resp in responses:
                    if isinstance(resp, Exception):
                        continue
                    if resp.status_code not in (429,):
                        success_count += 1

                if success_count >= 10:
                    # Check if endpoint actually exists (not 404)
                    check = await client.get(test_url)
                    if check.status_code != 404:
                        findings.append(
                            {
                                "severity": "medium",
                                "category": "rate_limit",
                                "title": f"No rate limiting on {endpoint}",
                                "description": f"Endpoint {endpoint} accepted {success_count}/10 rapid requests without rate limiting (HTTP 429).",
                                "evidence": f"10 rapid POST requests to {test_url}, {success_count} succeeded",
                                "recommendation": "Implement rate limiting on authentication endpoints (e.g., 5 requests/minute).",
                                "cwe_id": "CWE-307",
                                "cvss_score": 5.3,
                            }
                        )
            except (httpx.HTTPError, TimeoutError, OSError):
                continue

    return findings


async def check_cors_deep(url: str) -> list[dict]:
    """Deep CORS misconfiguration testing."""
    findings = []

    test_origins = [
        ("https://evil.com", "arbitrary origin"),
        ("null", "null origin"),
        (url.replace("://", "://evil."), "subdomain-like origin"),
    ]

    async with httpx.AsyncClient(timeout=SCAN_TIMEOUT, follow_redirects=True, verify=False) as client:
        for origin, desc in test_origins:
            try:
                resp = await client.get(url, headers={"Origin": origin})
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")

                if acao == origin:
                    severity = "high" if acac.lower() == "true" else "medium"
                    findings.append(
                        {
                            "severity": severity,
                            "category": "cors",
                            "title": f"CORS reflects {desc}",
                            "description": f"Server reflects Origin '{origin}' in Access-Control-Allow-Origin. "
                            + (
                                "Combined with Allow-Credentials, this allows credential theft."
                                if severity == "high"
                                else "Attacker can read responses from any origin."
                            ),
                            "evidence": f"Origin: {origin} -> ACAO: {acao}, ACAC: {acac}",
                            "recommendation": "Implement strict CORS origin whitelist. Never reflect arbitrary origins.",
                            "cwe_id": "CWE-942",
                            "cvss_score": 8.1 if severity == "high" else 5.3,
                        }
                    )

                elif acao == "null" and origin == "null":
                    findings.append(
                        {
                            "severity": "medium",
                            "category": "cors",
                            "title": "CORS allows null origin",
                            "description": "Server allows 'null' origin, which can be triggered by sandboxed iframes or local files.",
                            "evidence": "Origin: null -> ACAO: null",
                            "recommendation": "Do not allow 'null' as a valid origin in CORS policy.",
                            "cwe_id": "CWE-942",
                        }
                    )
            except (httpx.HTTPError, TimeoutError, OSError):
                continue

    return findings
