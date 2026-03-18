"""Web Crawler/Spider -- Discover links, forms, API endpoints, and static assets.

Crawls a target website to map its attack surface:
- Internal/external links
- Forms (login, search, upload)
- JavaScript files (potential API endpoints)
- Input fields and parameters
"""

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import httpx

from src.config import SCAN_TIMEOUT
from src.utils.logger import get_logger

log = get_logger("crawler")


class LinkParser(HTMLParser):
    """Extract links, forms, scripts, and inputs from HTML."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links = set()
        self.forms = []
        self.scripts = set()
        self.inputs = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        if tag == "a" and "href" in attrs_dict:
            href = attrs_dict["href"]
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                self.links.add(urljoin(self.base_url, href))

        elif tag == "form":
            self._current_form = {
                "action": urljoin(self.base_url, attrs_dict.get("action", "")),
                "method": attrs_dict.get("method", "GET").upper(),
                "inputs": [],
            }

        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append(
                {
                    "name": attrs_dict.get("name", ""),
                    "type": attrs_dict.get("type", "text"),
                    "value": attrs_dict.get("value", ""),
                }
            )

        elif tag == "input":
            self.inputs.append(
                {
                    "name": attrs_dict.get("name", ""),
                    "type": attrs_dict.get("type", "text"),
                }
            )

        elif tag == "script" and "src" in attrs_dict:
            self.scripts.add(urljoin(self.base_url, attrs_dict["src"]))

        elif tag == "link" and attrs_dict.get("rel") == "stylesheet":
            pass  # skip CSS

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form:
            self.forms.append(self._current_form)
            self._current_form = None


async def crawl(url: str, max_pages: int = 20, max_depth: int = 3) -> dict:
    """Spider a website and return its attack surface map.

    Returns:
        {
            "pages_crawled": int,
            "internal_links": list[str],
            "external_links": list[str],
            "forms": list[dict],
            "scripts": list[str],
            "api_endpoints": list[str],
            "parameters": list[str],
        }
    """
    parsed = urlparse(url)
    base_domain = parsed.netloc
    visited = set()
    to_visit = [(url, 0)]
    all_links = set()
    external_links = set()
    all_forms = []
    all_scripts = set()
    api_endpoints = set()
    parameters = set()

    async with httpx.AsyncClient(timeout=SCAN_TIMEOUT, follow_redirects=True, verify=False) as client:
        while to_visit and len(visited) < max_pages:
            current_url, depth = to_visit.pop(0)
            if current_url in visited:
                continue
            visited.add(current_url)

            try:
                resp = await client.get(current_url)
                content_type = resp.headers.get("content-type", "")
                if "text/html" not in content_type:
                    continue

                parser = LinkParser(current_url)
                parser.feed(resp.text)

                # Classify links
                for link in parser.links:
                    link_parsed = urlparse(link)
                    if link_parsed.netloc == base_domain or not link_parsed.netloc:
                        all_links.add(link)
                        if depth < max_depth and link not in visited:
                            to_visit.append((link, depth + 1))
                    else:
                        external_links.add(link)

                    # Extract query parameters
                    if link_parsed.query:
                        for param in link_parsed.query.split("&"):
                            name = param.split("=")[0]
                            if name:
                                parameters.add(name)

                # Collect forms
                for form in parser.forms:
                    all_forms.append(form)
                    for inp in form.get("inputs", []):
                        if inp.get("name"):
                            parameters.add(inp["name"])

                # Collect scripts and look for API patterns
                all_scripts.update(parser.scripts)

                # Find API endpoints in JS and HTML
                api_patterns = re.findall(r'["\']/(api|v[0-9]+|graphql|rest)/[^"\']*["\']', resp.text)
                for match in api_patterns:
                    if isinstance(match, tuple):
                        match = match[0]
                    # Reconstruct full pattern from the regex
                    pass

                # More thorough API endpoint extraction
                for pattern in re.findall(
                    r'["\'](/(?:api|v\d+|graphql|rest|auth|login|register|search|upload|webhook)[/\w.-]*)["\']',
                    resp.text,
                ):
                    api_endpoints.add(urljoin(url, pattern))

                # Find endpoints in JavaScript fetch/axios calls
                for pattern in re.findall(
                    r'(?:fetch|axios\.\w+|\.(?:get|post|put|delete|patch))\s*\(\s*["\']([^"\']+)["\']', resp.text
                ):
                    if pattern.startswith("/") or pattern.startswith("http"):
                        api_endpoints.add(urljoin(url, pattern))

            except (httpx.HTTPError, TimeoutError, OSError) as e:
                log.debug(f"Crawl error on {current_url}: {e}")

    return {
        "pages_crawled": len(visited),
        "internal_links": sorted(all_links),
        "external_links": sorted(external_links),
        "forms": all_forms,
        "scripts": sorted(all_scripts),
        "api_endpoints": sorted(api_endpoints),
        "parameters": sorted(parameters),
    }


async def check_crawl(url: str) -> list[dict]:
    """Run crawler and generate findings from the attack surface."""
    findings = []
    result = await crawl(url, max_pages=15, max_depth=2)

    # Report forms without CSRF protection
    for form in result["forms"]:
        has_csrf = any(
            inp.get("type") == "hidden"
            and any(tok in inp.get("name", "").lower() for tok in ["csrf", "token", "_token", "nonce"])
            for inp in form.get("inputs", [])
        )
        if form["method"] == "POST" and not has_csrf:
            findings.append(
                {
                    "severity": "medium",
                    "category": "crawler",
                    "title": f"Form without CSRF token: {form['action'][:80]}",
                    "description": f"POST form at {form['action']} has no visible CSRF token. May be vulnerable to CSRF attacks.",
                    "evidence": f"Method: {form['method']}, Action: {form['action']}, Inputs: {[i['name'] for i in form.get('inputs', [])]}",
                    "recommendation": "Add CSRF token to all state-changing forms.",
                    "cwe_id": "CWE-352",
                }
            )

    # Report login forms
    for form in result["forms"]:
        has_password = any(inp.get("type") == "password" for inp in form.get("inputs", []))
        if has_password:
            action_url = form["action"]
            parsed = urlparse(action_url)
            if parsed.scheme == "http":
                findings.append(
                    {
                        "severity": "critical",
                        "category": "crawler",
                        "title": "Login form submits over HTTP",
                        "description": f"Password form at {action_url} submits credentials over unencrypted HTTP.",
                        "evidence": f"Form action: {action_url}",
                        "recommendation": "Ensure all login forms submit over HTTPS.",
                        "cwe_id": "CWE-319",
                        "cvss_score": 9.0,
                    }
                )

    # Report exposed API endpoints
    if result["api_endpoints"]:
        findings.append(
            {
                "severity": "info",
                "category": "crawler",
                "title": f"Discovered {len(result['api_endpoints'])} API endpoints",
                "description": f"API endpoints found: {', '.join(result['api_endpoints'][:10])}",
                "evidence": f"Endpoints: {result['api_endpoints'][:20]}",
                "recommendation": "Ensure all API endpoints require proper authentication.",
            }
        )

    # Report external links (potential data leakage points)
    if len(result["external_links"]) > 20:
        findings.append(
            {
                "severity": "info",
                "category": "crawler",
                "title": f"{len(result['external_links'])} external links found",
                "description": "Large number of external links. Each is a potential data leakage point via Referer header.",
                "evidence": f"Sample: {result['external_links'][:5]}",
                "recommendation": "Use rel='noopener noreferrer' on external links and set Referrer-Policy header.",
            }
        )

    # Summary finding
    findings.append(
        {
            "severity": "info",
            "category": "crawler",
            "title": f"Attack surface: {result['pages_crawled']} pages, {len(result['forms'])} forms, {len(result['parameters'])} params",
            "description": (
                f"Crawled {result['pages_crawled']} pages. Found {len(result['internal_links'])} internal links, "
                f"{len(result['external_links'])} external links, {len(result['forms'])} forms, "
                f"{len(result['scripts'])} scripts, {len(result['api_endpoints'])} API endpoints, "
                f"{len(result['parameters'])} unique parameters."
            ),
            "evidence": f"Parameters: {result['parameters'][:20]}",
            "recommendation": "Review all discovered forms and API endpoints for proper security controls.",
        }
    )

    return findings
