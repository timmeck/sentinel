"""Report Export -- Generate JSON and HTML reports from scan results."""

import json
from datetime import datetime, timezone
from src.db.database import Database
from src.utils.logger import get_logger

log = get_logger("export")


async def export_json(db: Database, scan_id: int) -> str:
    """Export scan results as JSON."""
    scan = await db.get_scan(scan_id)
    if not scan:
        return json.dumps({"error": "Scan not found"})

    findings = await db.get_findings(scan_id)
    target = await db.get_target(scan["target_id"])

    report = {
        "sentinel_version": "1.0.0",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "target": {
            "url": target["url"] if target else "unknown",
            "name": target["name"] if target else "unknown",
        },
        "scan": {
            "id": scan_id,
            "type": scan["scan_type"],
            "status": scan["status"],
            "score": scan.get("score"),
            "started_at": scan.get("started_at"),
            "completed_at": scan.get("completed_at"),
        },
        "summary": {
            "total": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "medium": sum(1 for f in findings if f["severity"] == "medium"),
            "low": sum(1 for f in findings if f["severity"] == "low"),
            "info": sum(1 for f in findings if f["severity"] == "info"),
        },
        "findings": [
            {
                "severity": f["severity"],
                "category": f["category"],
                "title": f["title"],
                "description": f["description"],
                "evidence": f.get("evidence"),
                "recommendation": f.get("recommendation"),
                "cwe_id": f.get("cwe_id"),
                "cvss_score": f.get("cvss_score"),
            }
            for f in findings
        ],
        "report": scan.get("report"),
    }

    return json.dumps(report, indent=2)


async def export_html(db: Database, scan_id: int) -> str:
    """Export scan results as a standalone HTML report."""
    scan = await db.get_scan(scan_id)
    if not scan:
        return "<html><body><h1>Scan not found</h1></body></html>"

    findings = await db.get_findings(scan_id)
    target = await db.get_target(scan["target_id"])
    target_url = target["url"] if target else "unknown"
    score = scan.get("score", 0) or 0

    severity_counts = {}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    score_color = "#00ff88" if score >= 80 else "#ffaa00" if score >= 50 else "#ff4444"

    findings_html = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        sev_findings = [f for f in findings if f["severity"] == sev]
        if not sev_findings:
            continue

        sev_colors = {
            "critical": "#ff4444", "high": "#ff6b35",
            "medium": "#ffaa00", "low": "#00aaff", "info": "#999",
        }
        color = sev_colors.get(sev, "#999")

        findings_html += f'<h3 style="color:{color};margin-top:24px">{sev.upper()} ({len(sev_findings)})</h3>\n'
        for f in sev_findings:
            findings_html += f'''
            <div style="background:#12121a;border:1px solid #1a1a2e;border-left:4px solid {color};
                        border-radius:8px;padding:16px;margin:8px 0">
                <strong style="color:{color}">{f["title"]}</strong>
                <p style="color:#ccc;margin:8px 0">{f["description"]}</p>
                {"<p style='color:#888;font-size:0.85em'>Evidence: " + str(f.get("evidence", ""))[:200] + "</p>" if f.get("evidence") else ""}
                {"<p style='color:#00ff88;font-size:0.9em'>Fix: " + str(f.get("recommendation", "")) + "</p>" if f.get("recommendation") else ""}
                {"<span style='color:#666;font-size:0.8em'>" + str(f.get("cwe_id", "")) + "</span>" if f.get("cwe_id") else ""}
            </div>
            '''

    report_html = ""
    if scan.get("report"):
        report_html = f"<div style='background:#12121a;border:1px solid #1a1a2e;border-radius:8px;padding:20px;margin-top:24px;white-space:pre-wrap'>{scan['report']}</div>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sentinel Security Report — {target_url}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               background: #0a0a0f; color: #e0e0e0; max-width: 900px; margin: 0 auto; padding: 40px 20px; }}
        h1 {{ color: #00ff88; }} h2 {{ color: #ccc; border-bottom: 1px solid #1a1a2e; padding-bottom: 8px; }}
        a {{ color: #00ff88; }}
    </style>
</head>
<body>
    <h1>Sentinel Security Report</h1>
    <p>Target: <a href="{target_url}">{target_url}</a></p>
    <p>Scan ID: {scan_id} | Type: {scan["scan_type"]} | Date: {(scan.get("completed_at") or scan.get("created_at") or "?")[:16]}</p>

    <div style="text-align:center;margin:30px 0">
        <div style="font-size:3em;font-weight:700;color:{score_color}">{score:.0f}/100</div>
        <div style="color:#888">Security Score</div>
    </div>

    <div style="display:flex;gap:12px;justify-content:center;margin:20px 0">
        <span style="background:#ff444430;color:#ff4444;padding:4px 12px;border-radius:8px">Critical: {severity_counts.get("critical", 0)}</span>
        <span style="background:#ff6b3530;color:#ff6b35;padding:4px 12px;border-radius:8px">High: {severity_counts.get("high", 0)}</span>
        <span style="background:#ffaa0030;color:#ffaa00;padding:4px 12px;border-radius:8px">Medium: {severity_counts.get("medium", 0)}</span>
        <span style="background:#00aaff30;color:#00aaff;padding:4px 12px;border-radius:8px">Low: {severity_counts.get("low", 0)}</span>
        <span style="background:#66666630;color:#999;padding:4px 12px;border-radius:8px">Info: {severity_counts.get("info", 0)}</span>
    </div>

    <h2>Findings</h2>
    {findings_html}

    {"<h2>AI Analysis</h2>" + report_html if report_html else ""}

    <hr style="border-color:#1a1a2e;margin-top:40px">
    <p style="color:#666;font-size:0.8em;text-align:center">
        Generated by Sentinel — AI Security Scanner | {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
    </p>
</body>
</html>"""
