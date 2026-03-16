"""DNS & Subdomain Analysis -- DNS records, zone info, subdomain discovery."""

import asyncio
import socket
from urllib.parse import urlparse
import httpx
from src.config import SCAN_TIMEOUT
from src.utils.logger import get_logger

log = get_logger("dns")

# Common subdomains to probe
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "beta", "app", "portal", "cms", "blog", "shop", "store", "docs",
    "wiki", "support", "help", "status", "monitor", "dashboard",
    "cdn", "static", "assets", "media", "img", "images",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "vpn", "remote", "ssh", "git", "gitlab", "jenkins", "ci",
    "ns1", "ns2", "mx", "smtp", "pop", "imap",
    "internal", "intranet", "corp", "office",
    "sandbox", "demo", "qa", "uat", "preprod", "stage",
]


async def check_dns(url: str) -> list[dict]:
    """Analyze DNS configuration and discover subdomains."""
    findings = []
    parsed = urlparse(url)
    host = parsed.hostname
    domain = _get_base_domain(host)

    # DNS resolution
    try:
        ips = await asyncio.get_event_loop().run_in_executor(
            None, lambda: socket.getaddrinfo(host, None))
        ip_list = list(set(addr[4][0] for addr in ips))

        findings.append({
            "severity": "info",
            "category": "dns",
            "title": f"DNS resolves to {len(ip_list)} IP(s): {', '.join(ip_list[:5])}",
            "description": f"Domain {host} resolves to: {', '.join(ip_list)}",
            "evidence": f"IPs: {ip_list}",
            "recommendation": "Verify all IPs are expected and controlled by you.",
        })

        # Check for private IPs (potential internal exposure)
        for ip in ip_list:
            if ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                              "172.20.", "172.21.", "172.22.", "172.23.",
                              "172.24.", "172.25.", "172.26.", "172.27.",
                              "172.28.", "172.29.", "172.30.", "172.31.",
                              "192.168.", "127.")):
                findings.append({
                    "severity": "high",
                    "category": "dns",
                    "title": f"Domain resolves to private IP: {ip}",
                    "description": f"DNS points to private/internal IP {ip}. This may expose internal infrastructure.",
                    "evidence": f"IP: {ip}",
                    "recommendation": "Ensure public DNS records do not point to private IP addresses.",
                    "cwe_id": "CWE-200",
                })
    except Exception as e:
        findings.append({
            "severity": "medium",
            "category": "dns",
            "title": "DNS resolution failed",
            "description": f"Could not resolve {host}: {e}",
            "evidence": str(e),
            "recommendation": "Verify DNS configuration.",
        })

    # Check security-related DNS records
    await _check_dns_txt(domain, findings)

    # Subdomain enumeration
    discovered = await _enumerate_subdomains(domain)
    if discovered:
        risky = [s for s in discovered if any(kw in s for kw in
                 ["admin", "staging", "test", "dev", "internal", "jenkins", "git", "db", "database"])]

        findings.append({
            "severity": "info",
            "category": "dns",
            "title": f"Discovered {len(discovered)} subdomains",
            "description": f"Active subdomains: {', '.join(discovered[:15])}",
            "evidence": f"Subdomains: {discovered}",
            "recommendation": "Review all exposed subdomains. Restrict access to dev/staging/admin subdomains.",
        })

        if risky:
            findings.append({
                "severity": "medium",
                "category": "dns",
                "title": f"Sensitive subdomains exposed: {', '.join(risky[:5])}",
                "description": f"Subdomains that may expose internal/development infrastructure: {', '.join(risky)}",
                "evidence": f"Risky subdomains: {risky}",
                "recommendation": "Restrict access to sensitive subdomains via firewall or VPN.",
                "cwe_id": "CWE-200",
            })

    return findings


async def _check_dns_txt(domain: str, findings: list):
    """Check for SPF, DKIM, DMARC records."""
    try:
        # Check SPF
        records = await asyncio.get_event_loop().run_in_executor(
            None, lambda: socket.getaddrinfo(domain, None))
        # We can't do full TXT lookups with stdlib, but we can check via HTTP-based DNS
        async with httpx.AsyncClient(timeout=10) as client:
            # Use DNS-over-HTTPS (Cloudflare)
            for record_type, name_prefix in [("TXT", ""), ("TXT", "_dmarc.")]:
                query_name = f"{name_prefix}{domain}"
                try:
                    resp = await client.get(
                        f"https://cloudflare-dns.com/dns-query",
                        params={"name": query_name, "type": record_type},
                        headers={"Accept": "application/dns-json"},
                    )
                    data = resp.json()
                    answers = data.get("Answer", [])

                    txt_records = [a.get("data", "").strip('"') for a in answers if a.get("type") == 16]

                    if not name_prefix:
                        # Check SPF
                        spf = [r for r in txt_records if r.startswith("v=spf1")]
                        if not spf:
                            findings.append({
                                "severity": "low",
                                "category": "dns",
                                "title": "No SPF record found",
                                "description": "No SPF record. Email spoofing may be possible.",
                                "recommendation": "Add SPF record: v=spf1 include:_spf.google.com ~all (or similar).",
                            })
                    else:
                        # Check DMARC
                        dmarc = [r for r in txt_records if r.startswith("v=DMARC1")]
                        if not dmarc:
                            findings.append({
                                "severity": "low",
                                "category": "dns",
                                "title": "No DMARC record found",
                                "description": "No DMARC policy. Email authentication not enforced.",
                                "recommendation": "Add DMARC record: _dmarc.domain.com TXT 'v=DMARC1; p=reject'",
                            })
                        elif dmarc and "p=none" in dmarc[0]:
                            findings.append({
                                "severity": "low",
                                "category": "dns",
                                "title": "DMARC policy set to none",
                                "description": "DMARC is monitoring only (p=none). Spoofed emails won't be rejected.",
                                "evidence": f"DMARC: {dmarc[0][:100]}",
                                "recommendation": "Upgrade DMARC policy to 'p=quarantine' or 'p=reject'.",
                            })
                except Exception:
                    pass
    except Exception:
        pass


async def _enumerate_subdomains(domain: str) -> list[str]:
    """Discover active subdomains via DNS resolution."""
    discovered = []

    async def _probe(sub: str):
        fqdn = f"{sub}.{domain}"
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: socket.gethostbyname(fqdn))
            return fqdn
        except socket.gaierror:
            return None

    tasks = [_probe(sub) for sub in COMMON_SUBDOMAINS]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r]


def _get_base_domain(host: str) -> str:
    """Extract base domain from hostname."""
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host
