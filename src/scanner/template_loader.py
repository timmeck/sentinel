"""YAML-based Check Templates -- Load and execute security check templates.

Templates define HTTP-based security checks in YAML format:
- Request method and path(s)
- Matchers: status codes, body content, minimum response size
- Severity, CWE, description, recommendation

This allows adding new checks without writing Python code.
"""

import asyncio
from pathlib import Path

import httpx
import yaml

from src.config import SCAN_TIMEOUT
from src.utils.logger import get_logger

log = get_logger("templates")

TEMPLATES_DIR = Path(__file__).parent / "templates"


def load_templates(directory: Path | None = None) -> list[dict]:
    """Load all YAML check templates from the templates directory."""
    template_dir = directory or TEMPLATES_DIR
    templates = []

    if not template_dir.exists():
        log.warning(f"Templates directory not found: {template_dir}")
        return templates

    for yaml_file in sorted(template_dir.glob("*.yaml")):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                template = yaml.safe_load(f)
            if template and isinstance(template, dict) and "id" in template:
                template["_source"] = str(yaml_file.name)
                templates.append(template)
                log.debug(f"Loaded template: {template['id']} from {yaml_file.name}")
            else:
                log.warning(f"Invalid template (missing 'id'): {yaml_file}")
        except (yaml.YAMLError, OSError) as e:
            log.error(f"Failed to load template {yaml_file}: {e}")

    log.info(f"Loaded {len(templates)} check templates")
    return templates


def _get_paths(template: dict) -> list[str]:
    """Extract request paths from a template (supports 'path' or 'paths')."""
    request = template.get("request", {})
    if "paths" in request:
        return request["paths"]
    if "path" in request:
        return [request["path"]]
    return []


def _match_status(matcher: dict, status_code: int) -> bool:
    """Check if response status code matches."""
    return status_code in matcher.get("values", [])


def _match_body_contains(matcher: dict, body: str) -> bool:
    """Check if response body contains expected strings."""
    values = matcher.get("values", [])
    condition = matcher.get("condition", "any")
    body_lower = body.lower()

    if condition == "all":
        return all(v.lower() in body_lower for v in values)
    else:  # "any"
        return any(v.lower() in body_lower for v in values)


def _match_min_size(matcher: dict, content_length: int) -> bool:
    """Check if response body meets minimum size threshold."""
    return content_length >= matcher.get("value", 0)


def _check_matchers(template: dict, status_code: int, body: str, content_length: int) -> bool:
    """Evaluate all matchers for a template against a response. All matchers must pass."""
    matchers = template.get("matchers", [])
    if not matchers:
        return False

    for matcher in matchers:
        match_type = matcher.get("type", "")
        if match_type == "status":
            if not _match_status(matcher, status_code):
                return False
        elif match_type == "body_contains":
            if not _match_body_contains(matcher, body):
                return False
        elif match_type == "min_size":
            if not _match_min_size(matcher, content_length):
                return False
        else:
            log.warning(f"Unknown matcher type: {match_type}")
            return False

    return True


async def run_template_checks(url: str, templates: list[dict] | None = None) -> list[dict]:
    """Execute all YAML-defined check templates against a target URL.

    Args:
        url: Target base URL (e.g., https://example.com)
        templates: List of loaded templates. If None, loads from default directory.

    Returns:
        List of finding dicts compatible with the scan engine.
    """
    if templates is None:
        templates = load_templates()

    if not templates:
        return []

    findings = []
    from urllib.parse import urlparse

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    async with httpx.AsyncClient(timeout=SCAN_TIMEOUT, follow_redirects=False, verify=False) as client:
        sem = asyncio.Semaphore(10)

        async def _check_template(template: dict):
            """Run a single template check."""
            template_findings = []
            method = template.get("request", {}).get("method", "GET").upper()
            paths = _get_paths(template)

            for path in paths:
                async with sem:
                    try:
                        if method == "GET":
                            resp = await client.get(f"{base}{path}")
                        elif method == "POST":
                            resp = await client.post(f"{base}{path}")
                        elif method == "HEAD":
                            resp = await client.head(f"{base}{path}")
                        else:
                            resp = await client.request(method, f"{base}{path}")

                        body = resp.text[:10000]
                        content_length = len(resp.content)

                        if _check_matchers(template, resp.status_code, body, content_length):
                            template_findings.append(
                                {
                                    "severity": template.get("severity", "info"),
                                    "category": "template",
                                    "title": f"{template.get('name', template['id'])}: {path}",
                                    "description": template.get(
                                        "description",
                                        f"Template check '{template['id']}' matched on {path}.",
                                    ),
                                    "evidence": f"{method} {base}{path} -> {resp.status_code} ({content_length} bytes)",
                                    "recommendation": template.get(
                                        "recommendation", f"Investigate and restrict access to {path}."
                                    ),
                                    "cwe_id": template.get("cwe"),
                                    "cvss_score": template.get("cvss_score"),
                                }
                            )
                    except (httpx.HTTPError, TimeoutError, OSError) as e:
                        log.debug(f"Template {template['id']} failed for {path}: {e}")

            return template_findings

        tasks = [_check_template(t) for t in templates]
        results = await asyncio.gather(*tasks)

        for result in results:
            findings.extend(result)

    log.info(f"Template checks complete: {len(findings)} findings from {len(templates)} templates")
    return findings
