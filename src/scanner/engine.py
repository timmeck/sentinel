"""Scan Engine -- Orchestrates security checks and generates AI reports.

Pipeline:
1. Validate target URL
2. Run security checks (headers, SSL, ports, cookies, paths, tech)
3. Store findings in DB
4. Generate AI security report with recommendations
"""

from src.db.database import Database
from src.ai.llm import LLM
from src.scanner.checks import (
    check_headers, check_ssl, check_ports, check_cookies,
    check_paths, check_technology, check_https_redirect,
)
from src.utils.logger import get_logger

log = get_logger("engine")

# Scan types and their checks
SCAN_MODULES = {
    "headers": ("Security Headers", check_headers),
    "ssl": ("SSL/TLS Analysis", check_ssl),
    "ports": ("Port Scan", check_ports),
    "cookies": ("Cookie Security", check_cookies),
    "paths": ("Path Discovery", check_paths),
    "technology": ("Technology Detection", check_technology),
    "https_redirect": ("HTTPS Redirect", check_https_redirect),
}

SCAN_PROFILES = {
    "quick": ["headers", "ssl", "https_redirect", "technology"],
    "standard": ["headers", "ssl", "https_redirect", "cookies", "paths", "technology"],
    "full": list(SCAN_MODULES.keys()),
    "headers": ["headers"],
    "ssl": ["ssl", "https_redirect"],
    "ports": ["ports"],
    "recon": ["technology", "paths", "ports"],
}


class ScanEngine:
    def __init__(self, db: Database, llm: LLM):
        self.db = db
        self.llm = llm
        self.on_event = None  # SSE callback

    async def scan(self, url: str, scan_type: str = "full", target_name: str = None) -> dict:
        """Execute a security scan on a target URL."""
        # Normalize URL
        if not url.startswith("http"):
            url = f"https://{url}"

        # Get or create target
        target = await self.db.get_target_by_url(url)
        if not target:
            target = await self.db.create_target(url, name=target_name or url, target_type="web")

        # Create scan
        scan = await self.db.create_scan(target["id"], scan_type=scan_type)
        sid = scan["id"]

        await self._emit("scan_started", {"scan_id": sid, "url": url, "type": scan_type})
        await self.db.log_event("scan_started", f"Scanning {url} ({scan_type})", scan_id=sid)

        try:
            # Determine which checks to run
            checks = SCAN_PROFILES.get(scan_type, SCAN_PROFILES["full"])

            all_findings = []
            for check_name in checks:
                module_name, check_fn = SCAN_MODULES[check_name]
                await self._emit("check_running", {"scan_id": sid, "check": module_name})
                log.info(f"Running: {module_name}")

                try:
                    results = await check_fn(url)
                    for finding in results:
                        stored = await self.db.add_finding(
                            scan_id=sid,
                            severity=finding.get("severity", "info"),
                            category=finding.get("category", check_name),
                            title=finding["title"],
                            description=finding["description"],
                            evidence=finding.get("evidence"),
                            recommendation=finding.get("recommendation"),
                            cwe_id=finding.get("cwe_id"),
                            cvss_score=finding.get("cvss_score"),
                        )
                        all_findings.append(finding)
                except Exception as e:
                    log.error(f"Check {check_name} failed: {e}")
                    await self.db.log_event("check_failed", f"{module_name}: {e}", scan_id=sid)

            # Calculate security score
            score = self._calculate_score(all_findings)

            # Generate AI report
            await self._emit("step", {"scan_id": sid, "step": "Generating security report..."})
            report = await self._generate_report(url, all_findings, score)

            # Complete scan
            await self.db.update_scan(sid, status="completed", score=score,
                                       report=report, completed_at=self.db._now())
            await self.db.log_event("scan_completed",
                f"Scan complete: {len(all_findings)} findings, score {score}/100", scan_id=sid)
            await self._emit("scan_completed", {"scan_id": sid, "score": score,
                                                 "findings": len(all_findings)})

            return {
                "scan_id": sid,
                "target": url,
                "status": "completed",
                "score": score,
                "findings": len(all_findings),
                "critical": sum(1 for f in all_findings if f["severity"] == "critical"),
                "high": sum(1 for f in all_findings if f["severity"] == "high"),
                "medium": sum(1 for f in all_findings if f["severity"] == "medium"),
                "low": sum(1 for f in all_findings if f["severity"] == "low"),
                "info": sum(1 for f in all_findings if f["severity"] == "info"),
                "report": report,
            }

        except Exception as e:
            error = f"{type(e).__name__}: {e}"
            await self.db.update_scan(sid, status="failed")
            await self.db.log_event("scan_failed", error, scan_id=sid)
            await self._emit("scan_failed", {"scan_id": sid, "error": error})
            log.error(f"Scan failed: {e}", exc_info=True)
            return {"scan_id": sid, "status": "failed", "error": error}

    def _calculate_score(self, findings: list[dict]) -> float:
        """Calculate security score (0-100). Higher is better."""
        if not findings:
            return 100.0

        penalties = {"critical": 25, "high": 15, "medium": 5, "low": 2, "info": 0}
        total_penalty = sum(penalties.get(f["severity"], 0) for f in findings)
        return max(0.0, min(100.0, 100.0 - total_penalty))

    async def _generate_report(self, url: str, findings: list[dict], score: float) -> str:
        """Generate an AI-powered security report."""
        if not self.llm or not self.llm.is_healthy:
            return self._fallback_report(url, findings, score)

        # Build findings summary
        by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for f in findings:
            by_severity.get(f["severity"], by_severity["info"]).append(f)

        findings_text = ""
        for sev in ["critical", "high", "medium", "low"]:
            if by_severity[sev]:
                findings_text += f"\n### {sev.upper()} ({len(by_severity[sev])})\n"
                for f in by_severity[sev]:
                    findings_text += f"- {f['title']}: {f['description'][:150]}\n"

        prompt = (
            f"Write a concise security assessment report for: {url}\n\n"
            f"Security Score: {score}/100\n"
            f"Total Findings: {len(findings)} "
            f"({len(by_severity['critical'])} critical, {len(by_severity['high'])} high, "
            f"{len(by_severity['medium'])} medium, {len(by_severity['low'])} low)\n\n"
            f"Findings:\n{findings_text}\n\n"
            f"Structure:\n"
            f"1. Executive Summary (2-3 sentences)\n"
            f"2. Critical Issues (if any) — what to fix immediately\n"
            f"3. Key Recommendations (top 5 actionable items)\n"
            f"4. Overall Assessment\n\n"
            f"Be specific and actionable. Reference CWE IDs where relevant."
        )

        report = await self.llm.query(
            prompt,
            system="You are a senior security analyst writing a penetration test report. Be professional, specific, and actionable. Use markdown formatting.",
            max_tokens=2000,
        )
        return report or self._fallback_report(url, findings, score)

    def _fallback_report(self, url: str, findings: list[dict], score: float) -> str:
        """Generate a basic report without LLM."""
        lines = [
            f"# Security Scan Report: {url}",
            f"\n**Score:** {score}/100",
            f"**Total Findings:** {len(findings)}",
            "",
        ]

        by_severity = {}
        for f in findings:
            by_severity.setdefault(f["severity"], []).append(f)

        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in by_severity:
                lines.append(f"\n## {sev.upper()} ({len(by_severity[sev])})")
                for f in by_severity[sev]:
                    lines.append(f"- **{f['title']}**: {f['description'][:200]}")
                    if f.get("recommendation"):
                        lines.append(f"  - Fix: {f['recommendation']}")

        return "\n".join(lines)

    async def _emit(self, event_type: str, data: dict):
        if self.on_event:
            await self.on_event(event_type, data)
