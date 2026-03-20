"""FastAPI application for Sentinel -- AI Security Scanner."""

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse
from jinja2 import Template
from starlette.requests import Request

from src.ai.llm import LLM
from src.config import NEXUS_URL, SENTINEL_PORT
from src.db.database import Database
from src.nexus_sdk import NexusAdapter
from src.scanner.diff import compare_scans
from src.scanner.engine import SCAN_PROFILES, ScanEngine
from src.scanner.export import export_html, export_json
from src.scanner.scheduler import ScanScheduler
from src.utils.logger import get_logger
from src.web.auth import AuthMiddleware

log = get_logger("api")

db = Database()
llm = LLM()
engine = ScanEngine(db, llm)
scheduler = ScanScheduler(db, engine)
sse_clients: list[asyncio.Queue] = []


async def broadcast(event_type: str, data: dict):
    msg = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    for q in sse_clients[:]:
        try:
            q.put_nowait(msg)
        except (asyncio.QueueFull, Exception):
            sse_clients.remove(q)


engine.on_event = broadcast


@asynccontextmanager
async def lifespan(app):
    await db.initialize()
    await scheduler.ensure_table()
    await scheduler.start()
    yield
    await scheduler.stop()
    await db.close()


app = FastAPI(title="Sentinel", description="AI Security Scanner", lifespan=lifespan)
app.add_middleware(AuthMiddleware)

# ── Nexus Protocol Integration ─────────────────────────────────────
nexus = NexusAdapter(
    app=app,
    agent_name="sentinel",
    nexus_url=NEXUS_URL,
    endpoint=f"http://localhost:{SENTINEL_PORT}",
    description="AI Security Scanner — vulnerability detection and threat analysis",
    capabilities=[
        {
            "name": "security_analysis",
            "description": "Run security scan on a URL",
            "languages": ["en"],
            "price_per_request": 0.02,
        },
        {
            "name": "threat_detection",
            "description": "Quick threat detection check",
            "languages": ["en"],
            "price_per_request": 0.02,
        },
    ],
    tags=["security", "scanner", "vulnerability", "threat"],
)


@nexus.handle("security_analysis")
async def handle_security_analysis(query: str, params: dict) -> dict:
    scan_type = params.get("scan_type", "quick")
    result = await engine.scan(query, scan_type=scan_type, target_name="nexus-scan")
    answer = json.dumps(result, default=str) if isinstance(result, dict) else str(result)
    return {"result": answer, "confidence": 0.85, "cost": 0.02}


@nexus.handle("threat_detection")
async def handle_threat_detection(query: str, params: dict) -> dict:
    result = await engine.scan(query, scan_type="quick", target_name="nexus-threat-check")
    answer = json.dumps(result, default=str) if isinstance(result, dict) else str(result)
    return {"result": answer, "confidence": 0.90, "cost": 0.02}


# ── Status ──────────────────────────────────────────────────────────


@app.get("/api/status")
async def status():
    stats = await db.get_stats()
    return {"status": "ok", "llm_healthy": llm.is_healthy, "llm_provider": llm.provider, **stats}


# ── Targets ─────────────────────────────────────────────────────────


@app.get("/api/targets")
async def list_targets():
    return await db.list_targets()


@app.delete("/api/targets/{target_id}")
async def delete_target(target_id: int):
    ok = await db.delete_target(target_id)
    return {"deleted": ok}


# ── Scans ───────────────────────────────────────────────────────────


@app.post("/api/scan")
async def start_scan(request: Request, background_tasks: BackgroundTasks):
    body = await request.json()
    url = body.get("url", "").strip()
    scan_type = body.get("scan_type", "full")
    name = body.get("name")

    if not url:
        return {"error": "URL is required"}
    if scan_type not in SCAN_PROFILES:
        return {"error": f"Invalid scan_type. Options: {list(SCAN_PROFILES.keys())}"}

    # Run scan in background
    async def _run():
        await engine.scan(url, scan_type=scan_type, target_name=name)

    background_tasks.add_task(_run)
    return {"status": "started", "url": url, "scan_type": scan_type}


@app.post("/api/scan/sync")
async def scan_sync(request: Request):
    """Run scan synchronously and return results."""
    body = await request.json()
    url = body.get("url", "").strip()
    scan_type = body.get("scan_type", "full")
    name = body.get("name")

    if not url:
        return {"error": "URL is required"}

    result = await engine.scan(url, scan_type=scan_type, target_name=name)
    return result


@app.get("/api/scans")
async def list_scans(target_id: int | None = None):
    return await db.list_scans(target_id=target_id)


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: int):
    scan = await db.get_scan(scan_id)
    if not scan:
        return {"error": "Scan not found"}
    findings = await db.get_findings(scan_id)
    return {**scan, "findings": findings}


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: int):
    ok = await db.delete_scan(scan_id)
    return {"deleted": ok}


# ── Findings ────────────────────────────────────────────────────────


@app.get("/api/findings/search")
async def search_findings(q: str = "", limit: int = 20):
    if not q:
        return []
    return await db.search_findings(q, limit=limit)


# ── Activity ────────────────────────────────────────────────────────


@app.get("/api/activity")
async def get_activity(scan_id: int | None = None, limit: int = 50):
    return await db.get_activity(scan_id=scan_id, limit=limit)


# ── SSE ─────────────────────────────────────────────────────────────


@app.get("/api/events/stream")
async def event_stream():
    q = asyncio.Queue()
    sse_clients.append(q)

    async def generate():
        try:
            yield "event: connected\ndata: {}\n\n"
            while True:
                msg = await asyncio.wait_for(q.get(), timeout=30)
                yield msg
        except TimeoutError:
            yield "event: ping\ndata: {}\n\n"
        except (asyncio.CancelledError, OSError, RuntimeError):
            pass
        finally:
            if q in sse_clients:
                sse_clients.remove(q)

    return StreamingResponse(generate(), media_type="text/event-stream")


# ── Scan Profiles ───────────────────────────────────────────────────


@app.get("/api/profiles")
async def get_profiles():
    return {name: checks for name, checks in SCAN_PROFILES.items()}


# ── Schedules ───────────────────────────────────────────────────────


@app.get("/api/schedules")
async def list_schedules():
    return await scheduler.list_schedules()


@app.post("/api/schedules")
async def create_schedule(request: Request):
    body = await request.json()
    url = body.get("url", "").strip()
    interval = body.get("interval", "24h")
    scan_type = body.get("scan_type", "standard")
    if not url:
        return {"error": "URL required"}
    return await scheduler.add_schedule(url, interval, scan_type)


@app.delete("/api/schedules/{schedule_id}")
async def delete_schedule(schedule_id: int):
    return {"deleted": await scheduler.delete_schedule(schedule_id)}


@app.post("/api/schedules/{schedule_id}/toggle")
async def toggle_schedule(schedule_id: int):
    result = await scheduler.toggle_schedule(schedule_id)
    return result or {"error": "Schedule not found"}


# ── Diff/Compare ────────────────────────────────────────────────────


@app.get("/api/diff/{old_id}/{new_id}")
async def diff_scans(old_id: int, new_id: int):
    return await compare_scans(db, old_id, new_id)


@app.get("/api/scans/{id1}/diff/{id2}")
async def diff_scans_alt(id1: int, id2: int):
    """Compare two scan results: new findings, resolved findings, changed severity."""
    result = await compare_scans(db, id1, id2)
    if "error" in result:
        return result
    # Restructure into added/removed/changed format
    changed = []
    for finding in result.get("persistent_findings", []):
        fp = f"{finding.get('category', '')}::{finding.get('title', '')}"
        # Check if severity changed between old and new
        old_findings_map = {
            f"{f.get('category', '')}::{f.get('title', '')}": f
            for f in (await db.get_findings(id1))
        }
        old_f = old_findings_map.get(fp)
        if old_f and old_f.get("severity") != finding.get("severity"):
            changed.append({
                "title": finding.get("title"),
                "category": finding.get("category"),
                "old_severity": old_f.get("severity"),
                "new_severity": finding.get("severity"),
            })
    return {
        "scan_old": result["old_scan"],
        "scan_new": result["new_scan"],
        "score_change": result["score_change"],
        "added": result["new_findings"],
        "removed": result["resolved_findings"],
        "changed": changed,
        "summary": result["summary"],
    }


# ── Export ──────────────────────────────────────────────────────────


@app.get("/api/export/{scan_id}/json")
async def export_scan_json(scan_id: int):
    data = await export_json(db, scan_id)
    return StreamingResponse(
        iter([data]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=sentinel-scan-{scan_id}.json"},
    )


@app.get("/api/export/{scan_id}/html")
async def export_scan_html(scan_id: int):
    data = await export_html(db, scan_id)
    return HTMLResponse(data)


# ── Dashboard ───────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    template_path = Path(__file__).parent / "templates" / "dashboard.html"
    if template_path.exists():
        template = Template(template_path.read_text(encoding="utf-8"))
        stats = await db.get_stats()
        recent_scans = await db.list_scans(limit=10)
        return template.render(stats=stats, scans=recent_scans, port=SENTINEL_PORT)
    return HTMLResponse("<h1>Sentinel - AI Security Scanner</h1><p>Dashboard template not found.</p>")
