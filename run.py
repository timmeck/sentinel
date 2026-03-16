"""Sentinel -- AI Security Scanner.

Self-hosted security scanner with AI-powered analysis.
Scans web apps for vulnerabilities: headers, SSL, ports, cookies, paths.
Generates actionable reports with severity ratings and fix recommendations.
"""

import asyncio
import click
from src.db.database import Database
from src.ai.llm import LLM
from src.scanner.engine import ScanEngine, SCAN_PROFILES
from src.utils.logger import get_logger

log = get_logger("cli")


async def _services():
    db = Database()
    await db.initialize()
    llm = LLM()
    engine = ScanEngine(db, llm)
    return db, llm, engine


@click.group()
def cli():
    """Sentinel -- AI Security Scanner."""
    pass


@cli.command()
def status():
    """Show system status."""
    async def _run():
        db, llm, _ = await _services()
        stats = await db.get_stats()
        click.echo("\n[SENTINEL] AI Security Scanner\n")
        click.echo(f"  LLM: {llm.provider} ({'healthy' if llm.is_healthy else 'unhealthy'})")
        click.echo(f"  Model: {llm.model}")
        click.echo(f"  Targets: {stats['targets']}")
        click.echo(f"  Scans: {stats['scans']}")
        click.echo(f"  Findings: {stats['findings']}")
        click.echo(f"  Critical/High: {stats['critical_high']}")
        click.echo()
        await db.close()
    asyncio.run(_run())


@cli.command()
@click.argument("url")
@click.option("--type", "scan_type", default="full", help=f"Scan type: {list(SCAN_PROFILES.keys())}")
@click.option("--name", default=None, help="Target name")
def scan(url, scan_type, name):
    """Scan a target URL for security issues."""
    async def _run():
        db, llm, engine = await _services()
        click.echo(f"\nScanning {url} ({scan_type})...\n")
        result = await engine.scan(url, scan_type=scan_type, target_name=name)

        if result.get("error"):
            click.echo(f"FAILED: {result['error']}")
        else:
            score = result.get("score", 0)
            grade = "PASS" if score >= 80 else "WARN" if score >= 50 else "FAIL"
            click.echo(f"\n[{grade}] Score: {score:.0f}/100")
            click.echo(f"   Findings: {result.get('findings', 0)}")
            if result.get("critical", 0):
                click.echo(f"   [CRITICAL] {result['critical']}")
            if result.get("high", 0):
                click.echo(f"   [HIGH]     {result['high']}")
            if result.get("medium", 0):
                click.echo(f"   [MEDIUM]   {result['medium']}")
            if result.get("low", 0):
                click.echo(f"   [LOW]      {result['low']}")
            if result.get("info", 0):
                click.echo(f"   [INFO]     {result['info']}")

            click.echo(f"\n--- Report ---\n")
            click.echo(result.get("report", "No report generated."))

        click.echo()
        await db.close()
    asyncio.run(_run())


@cli.command()
@click.option("--limit", default=20, help="Number of scans to show")
def scans(limit):
    """List recent scans."""
    async def _run():
        db, _, _ = await _services()
        scan_list = await db.list_scans(limit=limit)
        if not scan_list:
            click.echo("No scans yet. Run: python run.py scan <url>")
            await db.close()
            return

        click.echo(f"\n{'ID':>4}  {'Score':>6}  {'Findings':>8}  {'Status':<10}  {'Type':<10}  URL")
        click.echo("-" * 80)
        for s in scan_list:
            score = f"{s['score']:.0f}" if s.get("score") is not None else "-"
            click.echo(f"{s['id']:>4}  {score:>6}  {s['findings_count']:>8}  {s['status']:<10}  {s['scan_type']:<10}  {s.get('url', '?')}")
        click.echo()
        await db.close()
    asyncio.run(_run())


@cli.command()
@click.argument("scan_id", type=int)
def show(scan_id):
    """Show scan details and findings."""
    async def _run():
        db, _, _ = await _services()
        scan = await db.get_scan(scan_id)
        if not scan:
            click.echo(f"Scan {scan_id} not found.")
            await db.close()
            return

        findings = await db.get_findings(scan_id)
        click.echo(f"\n[SENTINEL] Scan #{scan_id}")
        click.echo(f"   Status: {scan['status']}")
        click.echo(f"   Score: {scan.get('score', 'N/A')}")
        click.echo(f"   Findings: {len(findings)}")

        if findings:
            click.echo(f"\n{'Severity':<10}  {'Category':<12}  Title")
            click.echo("-" * 70)
            for f in findings:
                click.echo(f"  {f['severity']:<8}  {f['category']:<12}  {f['title']}")

        if scan.get("report"):
            click.echo(f"\n--- Report ---\n{scan['report']}")
        click.echo()
        await db.close()
    asyncio.run(_run())


@cli.command()
@click.argument("query")
@click.option("--limit", default=10)
def search(query, limit):
    """Search across all findings."""
    async def _run():
        db, _, _ = await _services()
        results = await db.search_findings(query, limit=limit)
        if not results:
            click.echo("No findings matched.")
        else:
            for f in results:
                click.echo(f"  [{f['severity']}] {f['title']}")
                click.echo(f"   {f['description'][:150]}")
                click.echo()
        await db.close()
    asyncio.run(_run())


@cli.command()
def targets():
    """List all scan targets."""
    async def _run():
        db, _, _ = await _services()
        target_list = await db.list_targets()
        if not target_list:
            click.echo("No targets yet.")
        else:
            for t in target_list:
                click.echo(f"  [{t['id']}] {t['name']} ({t['url']}) - {t['scan_count']} scans")
        click.echo()
        await db.close()
    asyncio.run(_run())


@cli.command()
@click.argument("old_id", type=int)
@click.argument("new_id", type=int)
def diff(old_id, new_id):
    """Compare two scans (regression tracking)."""
    async def _run():
        db, _, _ = await _services()
        from src.scanner.diff import compare_scans
        result = await compare_scans(db, old_id, new_id)
        if result.get("error"):
            click.echo(f"Error: {result['error']}")
            await db.close()
            return
        click.echo(f"\n{result['summary']}")
        if result["new_findings"]:
            click.echo(f"\n  NEW issues ({len(result['new_findings'])}):")
            for f in result["new_findings"]:
                click.echo(f"    + [{f['severity']}] {f['title']}")
        if result["resolved_findings"]:
            click.echo(f"\n  RESOLVED ({len(result['resolved_findings'])}):")
            for f in result["resolved_findings"]:
                click.echo(f"    - [{f['severity']}] {f['title']}")
        click.echo()
        await db.close()
    asyncio.run(_run())


@cli.command("export")
@click.argument("scan_id", type=int)
@click.option("--format", "fmt", default="json", help="Export format: json or html")
@click.option("--output", "-o", default=None, help="Output file path")
def export_cmd(scan_id, fmt, output):
    """Export scan report as JSON or HTML."""
    async def _run():
        db, _, _ = await _services()
        from src.scanner.export import export_json, export_html
        if fmt == "html":
            data = await export_html(db, scan_id)
        else:
            data = await export_json(db, scan_id)

        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(data)
            click.echo(f"Exported to {output}")
        else:
            click.echo(data)
        await db.close()
    asyncio.run(_run())


@cli.command()
@click.option("--port", default=None, type=int)
def serve(port):
    """Start the web dashboard."""
    import uvicorn
    from src.config import SENTINEL_PORT
    p = port or SENTINEL_PORT
    click.echo(f"\n[SENTINEL] Dashboard: http://localhost:{p}\n")
    uvicorn.run("src.web.api:app", host="0.0.0.0", port=p, reload=False)


if __name__ == "__main__":
    cli()
