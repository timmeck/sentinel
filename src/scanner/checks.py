"""Security checks -- Individual scan modules for web targets.

Each check function returns a list of finding dicts:
{severity, category, title, description, evidence, recommendation, cwe_id, cvss_score}
"""

import asyncio
import socket
import ssl
from urllib.parse import urlparse

import httpx

from src.config import SCAN_TIMEOUT
from src.utils.logger import get_logger

log = get_logger("checks")


# ── HTTP Security Headers ───────────────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "cwe": "CWE-319",
        "title": "Missing HSTS header",
        "desc": "Strict-Transport-Security header is not set. Browsers may connect over HTTP, exposing traffic to interception.",
        "rec": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "cwe": "CWE-79",
        "title": "Missing Content-Security-Policy",
        "desc": "No CSP header found. The application is more vulnerable to XSS attacks.",
        "rec": "Implement a Content-Security-Policy header that restricts script sources.",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "cwe": "CWE-16",
        "title": "Missing X-Content-Type-Options",
        "desc": "X-Content-Type-Options header is not set to 'nosniff'. Browsers may MIME-sniff responses.",
        "rec": "Add 'X-Content-Type-Options: nosniff' header.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "cwe": "CWE-1021",
        "title": "Missing X-Frame-Options",
        "desc": "X-Frame-Options is not set. The site may be vulnerable to clickjacking attacks.",
        "rec": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "cwe": "CWE-79",
        "title": "Missing X-XSS-Protection",
        "desc": "X-XSS-Protection header is not set. Legacy browsers lack XSS filtering.",
        "rec": "Add 'X-XSS-Protection: 1; mode=block' for legacy browser support.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "cwe": "CWE-200",
        "title": "Missing Referrer-Policy",
        "desc": "No Referrer-Policy header. Full URLs may leak to third parties via the Referer header.",
        "rec": "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
    },
    "Permissions-Policy": {
        "severity": "low",
        "cwe": "CWE-16",
        "title": "Missing Permissions-Policy",
        "desc": "No Permissions-Policy header. Browser features like camera, microphone, geolocation are not restricted.",
        "rec": "Add a Permissions-Policy header to restrict browser feature access.",
    },
}

DANGEROUS_HEADERS = {
    "Server": (
        "info",
        "Server header exposes software version",
        "Remove or obscure the Server header to reduce information leakage.",
    ),
    "X-Powered-By": ("low", "X-Powered-By header exposes technology stack", "Remove the X-Powered-By header."),
    "X-AspNet-Version": ("low", "ASP.NET version exposed", "Remove X-AspNet-Version header."),
}


async def check_headers(url: str) -> list[dict]:
    """Check HTTP security headers."""
    findings = []
    try:
        async with httpx.AsyncClient(timeout=SCAN_TIMEOUT, follow_redirects=True, verify=False) as client:
            resp = await client.get(url)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            # Check missing security headers
            for header, info in SECURITY_HEADERS.items():
                if header.lower() not in headers:
                    findings.append(
                        {
                            "severity": info["severity"],
                            "category": "headers",
                            "title": info["title"],
                            "description": info["desc"],
                            "evidence": f"Header '{header}' not found in response",
                            "recommendation": info["rec"],
                            "cwe_id": info["cwe"],
                        }
                    )

            # Check dangerous headers that leak info
            for header, (sev, desc, rec) in DANGEROUS_HEADERS.items():
                if header.lower() in headers:
                    findings.append(
                        {
                            "severity": sev,
                            "category": "headers",
                            "title": f"{header} header present: {headers[header.lower()]}",
                            "description": desc,
                            "evidence": f"{header}: {headers[header.lower()]}",
                            "recommendation": rec,
                            "cwe_id": "CWE-200",
                        }
                    )

            # Check for overly permissive CORS
            acao = headers.get("access-control-allow-origin", "")
            if acao == "*":
                findings.append(
                    {
                        "severity": "medium",
                        "category": "headers",
                        "title": "Wildcard CORS policy",
                        "description": "Access-Control-Allow-Origin is set to '*', allowing any origin to make requests.",
                        "evidence": f"Access-Control-Allow-Origin: {acao}",
                        "recommendation": "Restrict CORS to specific trusted origins.",
                        "cwe_id": "CWE-942",
                    }
                )

            # Check CSP quality if present
            csp = headers.get("content-security-policy", "")
            if csp:
                if "'unsafe-inline'" in csp:
                    findings.append(
                        {
                            "severity": "medium",
                            "category": "headers",
                            "title": "CSP allows unsafe-inline",
                            "description": "Content-Security-Policy contains 'unsafe-inline', weakening XSS protection.",
                            "evidence": f"CSP: {csp[:200]}",
                            "recommendation": "Remove 'unsafe-inline' and use nonces or hashes instead.",
                            "cwe_id": "CWE-79",
                        }
                    )
                if "'unsafe-eval'" in csp:
                    findings.append(
                        {
                            "severity": "medium",
                            "category": "headers",
                            "title": "CSP allows unsafe-eval",
                            "description": "Content-Security-Policy contains 'unsafe-eval', allowing dynamic code execution.",
                            "evidence": f"CSP: {csp[:200]}",
                            "recommendation": "Remove 'unsafe-eval' from CSP directives.",
                            "cwe_id": "CWE-79",
                        }
                    )

    except (httpx.HTTPError, TimeoutError, OSError) as e:
        log.warning(f"Header check failed for {url}: {e}")
    return findings


# ── SSL/TLS Analysis ────────────────────────────────────────────────


async def check_ssl(url: str) -> list[dict]:
    """Analyze SSL/TLS configuration."""
    findings = []
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        findings.append(
            {
                "severity": "high",
                "category": "ssl",
                "title": "No HTTPS",
                "description": "Target uses HTTP instead of HTTPS. All traffic is unencrypted.",
                "evidence": f"URL scheme: {parsed.scheme}",
                "recommendation": "Enable HTTPS with a valid TLS certificate.",
                "cwe_id": "CWE-319",
                "cvss_score": 7.5,
            }
        )
        return findings

    try:

        def _check():
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=SCAN_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()
                    return cert, protocol, cipher

        cert, protocol, cipher = await asyncio.get_event_loop().run_in_executor(None, _check)

        # Check protocol version
        if protocol and protocol in ("TLSv1", "TLSv1.1"):
            findings.append(
                {
                    "severity": "high",
                    "category": "ssl",
                    "title": f"Outdated TLS version: {protocol}",
                    "description": f"Server supports {protocol} which has known vulnerabilities.",
                    "evidence": f"Protocol: {protocol}",
                    "recommendation": "Disable TLS 1.0 and 1.1. Only allow TLS 1.2+.",
                    "cwe_id": "CWE-326",
                    "cvss_score": 7.4,
                }
            )

        # Check cipher strength
        if cipher and cipher[2] and cipher[2] < 128:
            findings.append(
                {
                    "severity": "high",
                    "category": "ssl",
                    "title": f"Weak cipher: {cipher[0]} ({cipher[2]} bits)",
                    "description": f"Cipher suite uses only {cipher[2]}-bit encryption.",
                    "evidence": f"Cipher: {cipher[0]}, Bits: {cipher[2]}",
                    "recommendation": "Configure server to use strong ciphers (AES-256-GCM, ChaCha20).",
                    "cwe_id": "CWE-326",
                }
            )

        # Check certificate expiry
        if cert:
            from datetime import datetime

            not_after = cert.get("notAfter", "")
            if not_after:
                try:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp - datetime.utcnow()).days
                    if days_left < 0:
                        findings.append(
                            {
                                "severity": "critical",
                                "category": "ssl",
                                "title": "SSL certificate expired",
                                "description": f"Certificate expired {abs(days_left)} days ago.",
                                "evidence": f"notAfter: {not_after}",
                                "recommendation": "Renew the SSL certificate immediately.",
                                "cwe_id": "CWE-295",
                                "cvss_score": 9.1,
                            }
                        )
                    elif days_left < 30:
                        findings.append(
                            {
                                "severity": "medium",
                                "category": "ssl",
                                "title": f"SSL certificate expiring soon ({days_left} days)",
                                "description": f"Certificate expires on {not_after}.",
                                "evidence": f"notAfter: {not_after}, days remaining: {days_left}",
                                "recommendation": "Renew the SSL certificate before expiry.",
                                "cwe_id": "CWE-295",
                            }
                        )
                except (ValueError, TypeError, OverflowError):
                    pass

        if not findings:
            findings.append(
                {
                    "severity": "info",
                    "category": "ssl",
                    "title": f"SSL/TLS OK: {protocol}, {cipher[0] if cipher else 'unknown'}",
                    "description": f"SSL configuration looks good. Protocol: {protocol}, Cipher: {cipher[0] if cipher else 'N/A'}.",
                    "evidence": f"Protocol: {protocol}, Cipher: {cipher}",
                    "recommendation": "No action needed.",
                }
            )

    except ssl.SSLCertVerificationError as e:
        findings.append(
            {
                "severity": "critical",
                "category": "ssl",
                "title": "SSL certificate verification failed",
                "description": f"Certificate validation error: {e}",
                "evidence": str(e),
                "recommendation": "Fix the SSL certificate chain. Ensure valid CA-signed certificate.",
                "cwe_id": "CWE-295",
                "cvss_score": 9.1,
            }
        )
    except (ssl.SSLError, OSError, socket.gaierror) as e:
        findings.append(
            {
                "severity": "info",
                "category": "ssl",
                "title": "SSL check inconclusive",
                "description": f"Could not complete SSL analysis: {e}",
                "evidence": str(e),
                "recommendation": "Verify SSL configuration manually.",
            }
        )

    return findings


# ── Port Scan ───────────────────────────────────────────────────────

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

RISKY_PORTS = {21, 23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 27017}


async def check_ports(url: str) -> list[dict]:
    """Scan common ports for open services."""
    findings = []
    parsed = urlparse(url)
    host = parsed.hostname

    async def _probe(port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3)
            writer.close()
            await writer.wait_closed()
            return True
        except (OSError, asyncio.TimeoutError):
            return False

    # Scan common ports concurrently
    tasks = {port: asyncio.create_task(_probe(port)) for port in COMMON_PORTS}
    open_ports = []
    for port, task in tasks.items():
        if await task:
            open_ports.append(port)

    for port in open_ports:
        service = COMMON_PORTS.get(port, "unknown")
        is_risky = port in RISKY_PORTS

        findings.append(
            {
                "severity": "high" if is_risky else "info",
                "category": "ports",
                "title": f"Port {port}/{service} open" + (" (risky)" if is_risky else ""),
                "description": f"Port {port} ({service}) is open and accepting connections."
                + (" This service should not be publicly exposed." if is_risky else ""),
                "evidence": f"TCP connect to {host}:{port} succeeded",
                "recommendation": f"Restrict access to port {port} via firewall rules."
                if is_risky
                else f"Verify port {port}/{service} is intentionally exposed.",
                "cwe_id": "CWE-200" if is_risky else None,
                "cvss_score": 7.5 if is_risky else None,
            }
        )

    return findings


# ── Cookie Security ─────────────────────────────────────────────────


async def check_cookies(url: str) -> list[dict]:
    """Check cookie security attributes."""
    findings = []
    try:
        async with httpx.AsyncClient(timeout=SCAN_TIMEOUT, follow_redirects=True, verify=False) as client:
            resp = await client.get(url)
            cookies = resp.headers.get_list("set-cookie")

            for cookie_str in cookies:
                parts = cookie_str.split(";")
                name = parts[0].split("=")[0].strip() if parts else "unknown"
                lower = cookie_str.lower()

                if "secure" not in lower:
                    findings.append(
                        {
                            "severity": "medium",
                            "category": "cookies",
                            "title": f"Cookie '{name}' missing Secure flag",
                            "description": "Cookie may be sent over HTTP.",
                            "evidence": cookie_str[:200],
                            "recommendation": "Add the Secure flag to all cookies.",
                            "cwe_id": "CWE-614",
                        }
                    )

                if "httponly" not in lower:
                    findings.append(
                        {
                            "severity": "medium",
                            "category": "cookies",
                            "title": f"Cookie '{name}' missing HttpOnly flag",
                            "description": "Cookie accessible via JavaScript, increasing XSS impact.",
                            "evidence": cookie_str[:200],
                            "recommendation": "Add the HttpOnly flag to prevent client-side access.",
                            "cwe_id": "CWE-1004",
                        }
                    )

                if "samesite" not in lower:
                    findings.append(
                        {
                            "severity": "low",
                            "category": "cookies",
                            "title": f"Cookie '{name}' missing SameSite attribute",
                            "description": "Cookie may be sent in cross-site requests (CSRF risk).",
                            "evidence": cookie_str[:200],
                            "recommendation": "Add 'SameSite=Strict' or 'SameSite=Lax'.",
                            "cwe_id": "CWE-352",
                        }
                    )

    except (httpx.HTTPError, TimeoutError, OSError) as e:
        log.warning(f"Cookie check failed for {url}: {e}")
    return findings


# ── Common Path Discovery ──────────────────────────────────────────

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/wp-admin/",
    "/wp-login.php",
    "/admin/",
    "/admin/login",
    "/api/",
    "/api/docs",
    "/api/swagger",
    "/graphql",
    "/.well-known/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/server-status",
    "/server-info",
    "/.htaccess",
    "/web.config",
    "/phpinfo.php",
    "/debug/",
    "/actuator/health",
    "/actuator/env",
    "/.DS_Store",
    "/backup/",
    "/dump.sql",
    "/database.sql",
    "/config.json",
    "/config.yaml",
    "/config.yml",
]


async def check_paths(url: str) -> list[dict]:
    """Discover sensitive or exposed paths."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    async with httpx.AsyncClient(timeout=SCAN_TIMEOUT, follow_redirects=False, verify=False) as client:
        sem = asyncio.Semaphore(10)

        async def _probe(path: str):
            async with sem:
                try:
                    resp = await client.get(f"{base}{path}")
                    return path, resp.status_code, len(resp.content)
                except (httpx.HTTPError, TimeoutError, OSError):
                    return path, None, 0

        tasks = [_probe(p) for p in SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks)

    for path, status, size in results:
        if status is None:
            continue

        if status == 200 and size > 0:
            # Determine severity based on path
            is_critical = any(
                p in path for p in [".env", ".git", "dump.sql", "database.sql", "phpinfo", "actuator/env"]
            )
            is_high = any(p in path for p in [".htaccess", "web.config", "config.json", "config.yaml", "backup"])
            is_info = any(p in path for p in ["robots.txt", "sitemap.xml", "security.txt", "api/docs", "swagger"])

            if is_critical:
                severity = "critical"
            elif is_high:
                severity = "high"
            elif is_info:
                severity = "info"
            else:
                severity = "medium"

            findings.append(
                {
                    "severity": severity,
                    "category": "paths",
                    "title": f"Accessible path: {path}",
                    "description": f"Path {path} returned HTTP {status} ({size} bytes)."
                    + (" This file may contain sensitive data!" if severity in ("critical", "high") else ""),
                    "evidence": f"GET {base}{path} → {status} ({size} bytes)",
                    "recommendation": f"Restrict access to {path} or remove it from the web root.",
                    "cwe_id": "CWE-538" if severity in ("critical", "high") else "CWE-200",
                    "cvss_score": 9.0 if severity == "critical" else 7.0 if severity == "high" else None,
                }
            )

    return findings


# ── Technology Detection ────────────────────────────────────────────


async def check_technology(url: str) -> list[dict]:
    """Detect web technologies and frameworks."""
    findings = []
    try:
        async with httpx.AsyncClient(timeout=SCAN_TIMEOUT, follow_redirects=True, verify=False) as client:
            resp = await client.get(url)
            body = resp.text[:50000].lower()
            headers = {k.lower(): v for k, v in resp.headers.items()}

            techs = []

            # Detect from headers
            server = headers.get("server", "")
            if server:
                techs.append(f"Server: {server}")
            powered = headers.get("x-powered-by", "")
            if powered:
                techs.append(f"X-Powered-By: {powered}")

            # Detect from body
            detections = [
                ("react" in body or "react-dom" in body, "React"),
                ("vue" in body or "__vue__" in body, "Vue.js"),
                ("angular" in body or "ng-app" in body, "Angular"),
                ("next" in body and "/_next/" in body, "Next.js"),
                ("nuxt" in body, "Nuxt.js"),
                ("wordpress" in body or "wp-content" in body, "WordPress"),
                ("django" in body or "csrfmiddlewaretoken" in body, "Django"),
                ("laravel" in body, "Laravel"),
                ("express" in headers.get("x-powered-by", "").lower(), "Express.js"),
                ("fastapi" in body or "swagger" in body, "FastAPI/OpenAPI"),
                ("jquery" in body, "jQuery"),
                ("bootstrap" in body, "Bootstrap"),
                ("tailwind" in body, "Tailwind CSS"),
            ]

            for match, name in detections:
                if match:
                    techs.append(name)

            if techs:
                findings.append(
                    {
                        "severity": "info",
                        "category": "technology",
                        "title": f"Detected technologies: {', '.join(techs[:5])}",
                        "description": f"The following technologies were detected: {', '.join(techs)}.",
                        "evidence": f"Technologies: {', '.join(techs)}",
                        "recommendation": "Keep all detected technologies up to date.",
                    }
                )

    except (httpx.HTTPError, TimeoutError, OSError) as e:
        log.warning(f"Technology check failed: {e}")
    return findings


# ── HTTPS Redirect ──────────────────────────────────────────────────


async def check_https_redirect(url: str) -> list[dict]:
    """Check if HTTP redirects to HTTPS."""
    findings = []
    parsed = urlparse(url)
    if parsed.scheme == "https":
        http_url = url.replace("https://", "http://", 1)
        try:
            async with httpx.AsyncClient(timeout=SCAN_TIMEOUT, follow_redirects=False, verify=False) as client:
                resp = await client.get(http_url)
                location = resp.headers.get("location", "")
                if resp.status_code in (301, 302, 307, 308) and "https" in location:
                    findings.append(
                        {
                            "severity": "info",
                            "category": "ssl",
                            "title": "HTTP redirects to HTTPS",
                            "description": f"HTTP request properly redirects to HTTPS ({resp.status_code}).",
                            "evidence": f"HTTP {resp.status_code} → {location}",
                            "recommendation": "No action needed.",
                        }
                    )
                else:
                    findings.append(
                        {
                            "severity": "medium",
                            "category": "ssl",
                            "title": "HTTP does not redirect to HTTPS",
                            "description": "HTTP requests are not redirected to HTTPS. Users may accidentally use unencrypted connections.",
                            "evidence": f"HTTP GET returned {resp.status_code}",
                            "recommendation": "Configure HTTP to redirect (301) to HTTPS.",
                            "cwe_id": "CWE-319",
                        }
                    )
        except (httpx.HTTPError, TimeoutError, OSError):
            pass
    return findings
