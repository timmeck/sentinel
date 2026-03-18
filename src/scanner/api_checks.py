"""API Security Checks -- Test API endpoints for common vulnerabilities.

Checks:
- GraphQL introspection (should be disabled in production)
- OpenAPI/Swagger exposure
- API versioning issues
- Missing authentication on API routes
- Verbose error messages
"""

import asyncio
from urllib.parse import urlparse

import httpx

from src.config import SCAN_TIMEOUT
from src.utils.logger import get_logger

log = get_logger("api_checks")

# Common API paths to probe
API_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/openapi.json",
    "/openapi.yaml",
    "/api/openapi.json",
    "/docs",
    "/api/docs",
    "/redoc",
    "/api/v1/",
    "/api/v2/",
    "/api/v3/",
    "/api/health",
    "/api/status",
    "/api/ping",
    "/api/users",
    "/api/admin",
    "/api/config",
    "/.well-known/openid-configuration",
    "/api/debug",
    "/api/test",
]

GRAPHQL_INTROSPECTION = '{"query": "{ __schema { types { name } } }"}'


async def check_api(url: str) -> list[dict]:
    """Run API security checks."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    async with httpx.AsyncClient(timeout=SCAN_TIMEOUT, follow_redirects=True, verify=False) as client:
        # Probe API paths
        sem = asyncio.Semaphore(10)

        async def _probe(path):
            async with sem:
                try:
                    resp = await client.get(f"{base}{path}")
                    return (
                        path,
                        resp.status_code,
                        resp.headers.get("content-type", ""),
                        len(resp.content),
                        resp.text[:2000],
                    )
                except Exception:
                    return path, None, "", 0, ""

        tasks = [_probe(p) for p in API_PATHS]
        results = await asyncio.gather(*tasks)

        exposed_apis = []
        for path, status, content_type, size, body in results:
            if status is None or status == 404:
                continue

            if status == 200 and size > 0:
                # Check for Swagger/OpenAPI exposure
                if any(kw in path for kw in ["swagger", "openapi", "api-docs"]):
                    if "application/json" in content_type or "swagger" in body.lower() or "openapi" in body.lower():
                        findings.append(
                            {
                                "severity": "medium",
                                "category": "api",
                                "title": f"API documentation exposed: {path}",
                                "description": f"API documentation/spec is publicly accessible at {path}. Attackers can study your API structure.",
                                "evidence": f"GET {base}{path} -> 200 ({size} bytes), Content-Type: {content_type}",
                                "recommendation": "Restrict API documentation to authenticated users or internal networks.",
                                "cwe_id": "CWE-200",
                            }
                        )
                        continue

                # Check for debug/config endpoints
                if any(kw in path for kw in ["/debug", "/config", "/admin"]):
                    findings.append(
                        {
                            "severity": "high",
                            "category": "api",
                            "title": f"Sensitive API endpoint accessible: {path}",
                            "description": f"Endpoint {path} is publicly accessible without authentication.",
                            "evidence": f"GET {base}{path} -> {status} ({size} bytes)",
                            "recommendation": f"Restrict access to {path} endpoint. Require authentication.",
                            "cwe_id": "CWE-284",
                            "cvss_score": 7.5,
                        }
                    )
                    continue

                exposed_apis.append(path)

            # Check for missing auth (200 on user/admin endpoints)
            if status == 200 and any(kw in path for kw in ["/users", "/admin"]):
                if "json" in content_type:
                    findings.append(
                        {
                            "severity": "high",
                            "category": "api",
                            "title": f"API endpoint returns data without auth: {path}",
                            "description": f"Endpoint {path} returns JSON data without requiring authentication.",
                            "evidence": f"GET {base}{path} -> 200, Content-Type: {content_type}",
                            "recommendation": "Require authentication (Bearer token, API key, session) on all data endpoints.",
                            "cwe_id": "CWE-306",
                            "cvss_score": 7.5,
                        }
                    )

            # Check for verbose error messages
            if status >= 500:
                if any(kw in body.lower() for kw in ["traceback", "stack trace", "exception", "debug", 'file "/']):
                    findings.append(
                        {
                            "severity": "medium",
                            "category": "api",
                            "title": f"Verbose error on {path} (HTTP {status})",
                            "description": "Server returns detailed error information including stack traces.",
                            "evidence": f"GET {base}{path} -> {status}, body contains debug info",
                            "recommendation": "Disable debug mode in production. Return generic error messages.",
                            "cwe_id": "CWE-209",
                        }
                    )

        # GraphQL introspection check
        for gql_path in ["/graphql", "/api/graphql", "/v1/graphql"]:
            try:
                resp = await client.post(
                    f"{base}{gql_path}",
                    content=GRAPHQL_INTROSPECTION,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 200 and "__schema" in resp.text:
                    findings.append(
                        {
                            "severity": "medium",
                            "category": "api",
                            "title": f"GraphQL introspection enabled: {gql_path}",
                            "description": "GraphQL introspection is enabled, exposing the full API schema including types, queries, and mutations.",
                            "evidence": f"POST {base}{gql_path} with introspection query -> 200",
                            "recommendation": "Disable GraphQL introspection in production.",
                            "cwe_id": "CWE-200",
                        }
                    )
            except Exception:
                continue

        # Summary
        if exposed_apis:
            findings.append(
                {
                    "severity": "info",
                    "category": "api",
                    "title": f"Found {len(exposed_apis)} accessible API endpoints",
                    "description": f"Accessible API endpoints: {', '.join(exposed_apis[:10])}",
                    "evidence": f"Endpoints: {exposed_apis}",
                    "recommendation": "Ensure all API endpoints have proper authentication and authorization.",
                }
            )

    return findings
