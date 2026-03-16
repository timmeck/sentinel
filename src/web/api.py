"""FastAPI application for Sentinel -- AI Security Scanner."""

import asyncio
import json
from contextlib import asynccontextmanager
from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import HTMLResponse, StreamingResponse
from starlette.requests import Request
from jinja2 import Template
from pathlib import Path
from src.db.database import Database
from src.ai.llm import LLM
from src.scanner.engine import ScanEngine, SCAN_PROFILES
from src.web.auth import AuthMiddleware
from src.config import SENTINEL_PORT
from src.utils.logger import get_logger

log = get_logger("api")

db = Database()
llm = LLM()
engine = ScanEngine(db, llm)
sse_clients: list[asyncio.Queue] = []


async def broadcast(event_type: str, data: dict):
    msg = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    for q in sse_clients[:]:
        try:
            q.put_nowait(msg)
        except Exception:
            sse_clients.remove(q)

engine.on_event = broadcast


@asynccontextmanager
async def lifespan(app):
    await db.initialize()
    yield
    await db.close()

app = FastAPI(title="Sentinel", description="AI Security Scanner", lifespan=lifespan)
app.add_middleware(AuthMiddleware)


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
async def list_scans(target_id: int = None):
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
async def get_activity(scan_id: int = None, limit: int = 50):
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
        except asyncio.TimeoutError:
            yield "event: ping\ndata: {}\n\n"
        except Exception:
            pass
        finally:
            if q in sse_clients:
                sse_clients.remove(q)

    return StreamingResponse(generate(), media_type="text/event-stream")


# ── Scan Profiles ───────────────────────────────────────────────────

@app.get("/api/profiles")
async def get_profiles():
    return {name: checks for name, checks in SCAN_PROFILES.items()}


# ── Dashboard ───────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    template_path = Path(__file__).parent / "templates" / "dashboard.html"
    if template_path.exists():
        template = Template(template_path.read_text())
        stats = await db.get_stats()
        recent_scans = await db.list_scans(limit=10)
        return template.render(stats=stats, scans=recent_scans, port=SENTINEL_PORT)
    return HTMLResponse("<h1>Sentinel - AI Security Scanner</h1><p>Dashboard template not found.</p>")
