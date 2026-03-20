"""API Fuzzer -- Basic fuzzing for APIs with OpenAPI/Swagger specs.

When a Swagger/OpenAPI spec is detected, parses it and tests:
- Auth bypass: Remove authorization headers on protected endpoints
- Method fuzzing: Try PUT/DELETE/PATCH on GET-only endpoints
- Path traversal in parameters: Inject traversal payloads in path/query params
"""

import asyncio
import json
from urllib.parse import urlparse

import httpx

from src.config import SCAN_TIMEOUT
from src.utils.logger import get_logger

log = get_logger("api_fuzzer")

# Common OpenAPI spec locations
SPEC_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/api/openapi.json",
    "/openapi.yaml",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/api-docs",
]

# Methods to try on endpoints that don't explicitly allow them
FUZZ_METHODS = ["PUT", "DELETE", "PATCH"]

# Path traversal payloads for parameter fuzzing
TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
]

TRAVERSAL_INDICATORS = [
    "root:x:",
    "root:*:",
    "[fonts]",
    "[extensions]",
    "/bin/bash",
    "/bin/sh",
]


async def _fetch_openapi_spec(client: httpx.AsyncClient, base: str) -> dict | None:
    """Try to find and fetch an OpenAPI/Swagger spec."""
    for path in SPEC_PATHS:
        try:
            resp = await client.get(f"{base}{path}")
            if resp.status_code == 200:
                ct = resp.headers.get("content-type", "")
                body = resp.text[:50000]
                if "json" in ct or body.strip().startswith("{"):
                    spec = json.loads(body)
                    # Validate it looks like an OpenAPI spec
                    if "paths" in spec or "swagger" in spec or "openapi" in spec:
                        log.info(f"Found OpenAPI spec at {path}")
                        return spec
        except (httpx.HTTPError, TimeoutError, OSError, json.JSONDecodeError):
            continue
    return None


def _extract_endpoints(spec: dict) -> list[dict]:
    """Extract endpoint definitions from an OpenAPI spec.

    Returns list of {path, methods, parameters} dicts.
    """
    endpoints = []
    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        methods = []
        parameters = []

        for key, value in path_item.items():
            if key.lower() in ("get", "post", "put", "delete", "patch", "options", "head"):
                methods.append(key.upper())
                # Collect parameters
                if isinstance(value, dict):
                    params = value.get("parameters", [])
                    for p in params:
                        if isinstance(p, dict):
                            parameters.append(
                                {
                                    "name": p.get("name", ""),
                                    "in": p.get("in", "query"),
                                    "required": p.get("required", False),
                                }
                            )

            # Path-level parameters
            if key == "parameters" and isinstance(value, list):
                for p in value:
                    if isinstance(p, dict):
                        parameters.append(
                            {
                                "name": p.get("name", ""),
                                "in": p.get("in", "query"),
                                "required": p.get("required", False),
                            }
                        )

        if methods:
            endpoints.append({"path": path, "methods": methods, "parameters": parameters})

    return endpoints


async def _fuzz_auth_bypass(
    client: httpx.AsyncClient, base: str, endpoints: list[dict], sem: asyncio.Semaphore
) -> list[dict]:
    """Test endpoints without auth headers to detect auth bypass."""
    findings = []

    # Pick endpoints that look like they should be protected
    protected_keywords = ["admin", "user", "account", "config", "settings", "private", "internal", "manage"]

    for ep in endpoints:
        path = ep["path"]
        if not any(kw in path.lower() for kw in protected_keywords):
            continue

        async with sem:
            try:
                # Request without any auth
                resp = await client.get(f"{base}{path}", headers={"Authorization": ""})
                if resp.status_code == 200 and len(resp.content) > 50:
                    ct = resp.headers.get("content-type", "")
                    if "json" in ct or "html" in ct:
                        findings.append(
                            {
                                "severity": "high",
                                "category": "api_fuzz",
                                "title": f"Potential auth bypass: {path}",
                                "description": f"Endpoint {path} returns data (HTTP 200, {len(resp.content)} bytes) without authentication headers.",
                                "evidence": f"GET {base}{path} without auth -> 200 ({len(resp.content)} bytes)",
                                "recommendation": "Enforce authentication on all sensitive endpoints. Return 401/403 for unauthenticated requests.",
                                "cwe_id": "CWE-306",
                                "cvss_score": 7.5,
                            }
                        )
            except (httpx.HTTPError, TimeoutError, OSError):
                continue

    return findings


async def _fuzz_methods(
    client: httpx.AsyncClient, base: str, endpoints: list[dict], sem: asyncio.Semaphore
) -> list[dict]:
    """Try unexpected HTTP methods on endpoints."""
    findings = []

    for ep in endpoints:
        path = ep["path"]
        allowed = set(ep["methods"])

        # Skip if endpoint already allows destructive methods
        if {"PUT", "DELETE", "PATCH"} & allowed:
            continue

        for method in FUZZ_METHODS:
            if method in allowed:
                continue

            async with sem:
                try:
                    resp = await client.request(method, f"{base}{path}")
                    # If server accepts the method (not 405 Method Not Allowed)
                    if resp.status_code not in (405, 404, 501):
                        findings.append(
                            {
                                "severity": "medium",
                                "category": "api_fuzz",
                                "title": f"Unexpected method accepted: {method} {path}",
                                "description": f"Endpoint {path} accepts {method} (HTTP {resp.status_code}) but only declares {', '.join(sorted(allowed))} in the spec.",
                                "evidence": f"{method} {base}{path} -> {resp.status_code}",
                                "recommendation": f"Restrict {path} to declared methods only. Return 405 for unsupported methods.",
                                "cwe_id": "CWE-749",
                            }
                        )
                        break  # One finding per path is enough
                except (httpx.HTTPError, TimeoutError, OSError):
                    continue

    return findings


async def _fuzz_traversal(
    client: httpx.AsyncClient, base: str, endpoints: list[dict], sem: asyncio.Semaphore
) -> list[dict]:
    """Inject path traversal payloads into API parameters."""
    findings = []

    for ep in endpoints:
        path = ep["path"]
        params = ep["parameters"]

        # Test path parameters (e.g., /api/files/{filename})
        path_params = [p for p in params if p["in"] == "path"]
        query_params = [p for p in params if p["in"] == "query"]

        # Also detect path params from template syntax
        import re

        template_params = re.findall(r"\{(\w+)\}", path)

        # Test path traversal via query parameters with file-like names
        file_keywords = ["file", "path", "name", "doc", "template", "include", "page", "dir", "folder", "resource"]
        file_params = [p for p in query_params if any(kw in p["name"].lower() for kw in file_keywords)]

        for param in file_params:
            for payload in TRAVERSAL_PAYLOADS[:2]:  # Limit payloads for speed
                async with sem:
                    try:
                        test_path = path
                        # Replace any path templates with safe values
                        for tp in template_params:
                            test_path = test_path.replace(f"{{{tp}}}", "1")

                        resp = await client.get(f"{base}{test_path}", params={param["name"]: payload})
                        body = resp.text[:5000]

                        for indicator in TRAVERSAL_INDICATORS:
                            if indicator in body:
                                findings.append(
                                    {
                                        "severity": "critical",
                                        "category": "api_fuzz",
                                        "title": f"Path traversal in API param '{param['name']}': {path}",
                                        "description": f"Path traversal payload in parameter '{param['name']}' exposed system files via {path}.",
                                        "evidence": f"GET {base}{test_path}?{param['name']}={payload} -> indicator '{indicator}' found",
                                        "recommendation": f"Validate and sanitize parameter '{param['name']}'. Use allowlists for file access.",
                                        "cwe_id": "CWE-22",
                                        "cvss_score": 9.1,
                                    }
                                )
                                break
                    except (httpx.HTTPError, TimeoutError, OSError):
                        continue

        # Test path parameters with traversal
        for tp in template_params:
            for payload in TRAVERSAL_PAYLOADS[:2]:
                async with sem:
                    try:
                        test_path = path.replace(f"{{{tp}}}", payload)
                        # Replace other path templates with safe values
                        for other_tp in template_params:
                            if other_tp != tp:
                                test_path = test_path.replace(f"{{{other_tp}}}", "1")

                        resp = await client.get(f"{base}{test_path}")
                        body = resp.text[:5000]

                        for indicator in TRAVERSAL_INDICATORS:
                            if indicator in body:
                                findings.append(
                                    {
                                        "severity": "critical",
                                        "category": "api_fuzz",
                                        "title": f"Path traversal via path param '{tp}': {path}",
                                        "description": f"Path traversal payload in path parameter '{tp}' exposed system files.",
                                        "evidence": f"GET {base}{test_path} -> indicator '{indicator}' found",
                                        "recommendation": f"Validate path parameter '{tp}'. Reject directory traversal characters.",
                                        "cwe_id": "CWE-22",
                                        "cvss_score": 9.1,
                                    }
                                )
                                break
                    except (httpx.HTTPError, TimeoutError, OSError):
                        continue

    return findings


async def fuzz_api(url: str) -> list[dict]:
    """Run API fuzzing checks.

    Attempts to find and parse an OpenAPI/Swagger spec, then fuzzes:
    1. Auth bypass on sensitive-looking endpoints
    2. HTTP method fuzzing (PUT/DELETE on GET-only endpoints)
    3. Path traversal in parameters

    Args:
        url: Target base URL.

    Returns:
        List of finding dicts.
    """
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    async with httpx.AsyncClient(timeout=SCAN_TIMEOUT, follow_redirects=True, verify=False) as client:
        # Step 1: Find OpenAPI spec
        spec = await _fetch_openapi_spec(client, base)
        if not spec:
            log.info("No OpenAPI/Swagger spec found, skipping API fuzzing")
            return findings

        # Step 2: Extract endpoints
        endpoints = _extract_endpoints(spec)
        if not endpoints:
            log.info("No endpoints found in OpenAPI spec")
            return findings

        log.info(f"Found {len(endpoints)} API endpoints in spec, starting fuzz tests")

        findings.append(
            {
                "severity": "info",
                "category": "api_fuzz",
                "title": f"OpenAPI spec found with {len(endpoints)} endpoints",
                "description": f"Parsed OpenAPI specification with {len(endpoints)} endpoint definitions for fuzz testing.",
                "evidence": f"Endpoints: {', '.join(ep['path'] for ep in endpoints[:10])}",
                "recommendation": "Restrict API spec access to authenticated users.",
            }
        )

        sem = asyncio.Semaphore(5)

        # Step 3: Run fuzz tests
        auth_findings = await _fuzz_auth_bypass(client, base, endpoints, sem)
        method_findings = await _fuzz_methods(client, base, endpoints, sem)
        traversal_findings = await _fuzz_traversal(client, base, endpoints, sem)

        findings.extend(auth_findings)
        findings.extend(method_findings)
        findings.extend(traversal_findings)

    log.info(f"API fuzzing complete: {len(findings)} findings")
    return findings
