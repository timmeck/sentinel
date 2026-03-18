"""Database layer for Sentinel -- AI Security Scanner."""

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import aiosqlite

from src.ai.embeddings import embed_text, search_similar, store_embedding
from src.ai.embeddings import ensure_table as ensure_embeddings_table
from src.config import DB_PATH
from src.utils.logger import get_logger

log = get_logger("db")

SCHEMA = """
-- Scan targets
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    name TEXT,
    target_type TEXT DEFAULT 'web',
    last_scanned_at TEXT,
    scan_count INTEGER DEFAULT 0,
    created_at TEXT NOT NULL
);

-- Scans
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    scan_type TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    findings_count INTEGER DEFAULT 0,
    score REAL,
    report TEXT,
    started_at TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

-- Findings (vulnerabilities, issues, recommendations)
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    severity TEXT DEFAULT 'info',
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT,
    recommendation TEXT,
    cwe_id TEXT,
    cvss_score REAL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Activity log
CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    data TEXT,
    created_at TEXT NOT NULL
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_activity ON activity_log(created_at DESC);
"""

FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
    title, description, recommendation,
    content='findings', content_rowid='id'
);
"""


class Database:
    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or DB_PATH
        self.conn: aiosqlite.Connection | None = None

    async def initialize(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = await aiosqlite.connect(str(self.db_path))
        self.conn.row_factory = aiosqlite.Row
        await self.conn.execute("PRAGMA journal_mode=WAL")
        await self.conn.execute("PRAGMA foreign_keys=ON")
        await self.conn.executescript(SCHEMA)
        for s in FTS_SCHEMA.strip().split(";"):
            s = s.strip()
            if s:
                try:
                    await self.conn.execute(s)
                except (sqlite3.OperationalError, sqlite3.ProgrammingError):
                    pass
        await self.conn.commit()
        await ensure_embeddings_table(self.conn)
        log.info(f"Database initialized: {self.db_path}")

    async def close(self):
        if self.conn:
            await self.conn.close()
            self.conn = None

    def _now(self) -> str:
        return datetime.now(UTC).isoformat()

    # ── Targets ─────────────────────────────────────────────────────

    async def create_target(self, url: str, name: str | None = None, target_type: str = "web") -> dict:
        now = self._now()
        cursor = await self.conn.execute(
            "INSERT INTO targets (url, name, target_type, created_at) VALUES (?, ?, ?, ?)",
            (url, name or url, target_type, now),
        )
        await self.conn.commit()
        return await self.get_target(cursor.lastrowid)

    async def get_target(self, target_id: int) -> dict | None:
        c = await self.conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
        r = await c.fetchone()
        return dict(r) if r else None

    async def get_target_by_url(self, url: str) -> dict | None:
        c = await self.conn.execute("SELECT * FROM targets WHERE url = ?", (url,))
        r = await c.fetchone()
        return dict(r) if r else None

    async def list_targets(self, limit: int = 50) -> list[dict]:
        c = await self.conn.execute("SELECT * FROM targets ORDER BY created_at DESC LIMIT ?", (limit,))
        return [dict(r) for r in await c.fetchall()]

    async def delete_target(self, target_id: int) -> bool:
        # Cascade: delete scans and findings
        scans = await self.conn.execute("SELECT id FROM scans WHERE target_id = ?", (target_id,))
        for scan in await scans.fetchall():
            await self.conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan["id"],))
        await self.conn.execute("DELETE FROM scans WHERE target_id = ?", (target_id,))
        cur = await self.conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
        await self.conn.commit()
        return cur.rowcount > 0

    # ── Scans ───────────────────────────────────────────────────────

    async def create_scan(self, target_id: int, scan_type: str = "full") -> dict:
        now = self._now()
        cursor = await self.conn.execute(
            "INSERT INTO scans (target_id, scan_type, status, started_at, created_at) VALUES (?, ?, 'running', ?, ?)",
            (target_id, scan_type, now, now),
        )
        await self.conn.execute(
            "UPDATE targets SET scan_count = scan_count + 1, last_scanned_at = ? WHERE id = ?", (now, target_id)
        )
        await self.conn.commit()
        return await self.get_scan(cursor.lastrowid)

    async def get_scan(self, scan_id: int) -> dict | None:
        c = await self.conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        r = await c.fetchone()
        return dict(r) if r else None

    async def list_scans(self, target_id: int | None = None, limit: int = 50) -> list[dict]:
        if target_id:
            c = await self.conn.execute(
                "SELECT s.*, t.url, t.name as target_name FROM scans s JOIN targets t ON t.id = s.target_id "
                "WHERE s.target_id = ? ORDER BY s.created_at DESC LIMIT ?",
                (target_id, limit),
            )
        else:
            c = await self.conn.execute(
                "SELECT s.*, t.url, t.name as target_name FROM scans s JOIN targets t ON t.id = s.target_id "
                "ORDER BY s.created_at DESC LIMIT ?",
                (limit,),
            )
        return [dict(r) for r in await c.fetchall()]

    async def update_scan(self, scan_id: int, **kwargs):
        sets = ", ".join(f"{k} = ?" for k in kwargs)
        vals = [*list(kwargs.values()), scan_id]
        await self.conn.execute(f"UPDATE scans SET {sets} WHERE id = ?", vals)
        await self.conn.commit()

    async def delete_scan(self, scan_id: int) -> bool:
        await self.conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        cur = await self.conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        await self.conn.commit()
        return cur.rowcount > 0

    # ── Findings ────────────────────────────────────────────────────

    async def add_finding(
        self,
        scan_id: int,
        severity: str,
        category: str,
        title: str,
        description: str,
        evidence: str | None = None,
        recommendation: str | None = None,
        cwe_id: str | None = None,
        cvss_score: float | None = None,
    ) -> dict:
        now = self._now()
        cursor = await self.conn.execute(
            "INSERT INTO findings (scan_id, severity, category, title, description, "
            "evidence, recommendation, cwe_id, cvss_score, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, severity, category, title, description, evidence, recommendation, cwe_id, cvss_score, now),
        )
        fid = cursor.lastrowid
        # FTS index
        try:
            await self.conn.execute(
                "INSERT INTO findings_fts(rowid, title, description, recommendation) VALUES (?, ?, ?, ?)",
                (fid, title, description, recommendation or ""),
            )
        except (sqlite3.OperationalError, sqlite3.ProgrammingError):
            pass
        # Update findings count
        await self.conn.execute("UPDATE scans SET findings_count = findings_count + 1 WHERE id = ?", (scan_id,))
        await self.conn.commit()
        # Embed finding
        vector = await embed_text(f"{title} {description}")
        if vector:
            await store_embedding(self.conn, "findings", fid, vector)
        return {"id": fid, "severity": severity, "title": title}

    async def get_findings(self, scan_id: int) -> list[dict]:
        severity_order = (
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
        )
        c = await self.conn.execute(f"SELECT * FROM findings WHERE scan_id = ? ORDER BY {severity_order}", (scan_id,))
        return [dict(r) for r in await c.fetchall()]

    async def search_findings(self, query: str, limit: int = 10) -> list[dict]:
        """Hybrid search: semantic + FTS5."""
        semantic_scores = {}
        query_vector = await embed_text(query)
        if query_vector:
            similar = await search_similar(self.conn, query_vector, "findings", limit=limit * 2)
            for item in similar:
                semantic_scores[item["source_id"]] = item["similarity"]

        fts_scores = {}
        fts_lookup = {}
        try:
            c = await self.conn.execute(
                """
                SELECT f.*, rank FROM findings_fts fts
                JOIN findings f ON f.id = fts.rowid
                WHERE findings_fts MATCH ?
                ORDER BY rank LIMIT ?
            """,
                (query, limit * 2),
            )
            fts_results = await c.fetchall()
            if fts_results:
                ranks = [abs(dict(r).get("rank", 0)) for r in fts_results]
                max_rank = max(ranks) if ranks else 1.0
                for r in fts_results:
                    row = dict(r)
                    fts_scores[row["id"]] = 1.0 - (abs(row.get("rank", 0)) / max_rank) if max_rank else 0.5
                    fts_lookup[row["id"]] = row
        except (sqlite3.OperationalError, sqlite3.ProgrammingError):
            pass

        all_ids = set(semantic_scores.keys()) | set(fts_scores.keys())
        if all_ids:
            hybrid = []
            for fid in all_ids:
                sem = semantic_scores.get(fid, 0.0)
                fts = fts_scores.get(fid, 0.0)
                hybrid.append((fid, 0.6 * sem + 0.4 * fts))
            hybrid.sort(key=lambda x: x[1], reverse=True)

            results = []
            for fid, score in hybrid[:limit]:
                if fid in fts_lookup:
                    results.append(fts_lookup[fid])
                else:
                    c = await self.conn.execute("SELECT * FROM findings WHERE id = ?", (fid,))
                    row = await c.fetchone()
                    if row:
                        results.append(dict(row))
            return results

        # Fallback
        c = await self.conn.execute(
            "SELECT * FROM findings WHERE description LIKE ? OR title LIKE ? LIMIT ?",
            (f"%{query}%", f"%{query}%", limit),
        )
        return [dict(r) for r in await c.fetchall()]

    # ── Activity Log ────────────────────────────────────────────────

    async def log_event(self, event_type: str, message: str, scan_id: int | None = None, data: dict | None = None):
        await self.conn.execute(
            "INSERT INTO activity_log (scan_id, event_type, message, data, created_at) VALUES (?, ?, ?, ?, ?)",
            (scan_id, event_type, message, json.dumps(data, default=str) if data else None, self._now()),
        )
        await self.conn.commit()

    async def get_activity(self, scan_id: int | None = None, limit: int = 50) -> list[dict]:
        if scan_id:
            c = await self.conn.execute(
                "SELECT * FROM activity_log WHERE scan_id = ? ORDER BY created_at DESC LIMIT ?", (scan_id, limit)
            )
        else:
            c = await self.conn.execute("SELECT * FROM activity_log ORDER BY created_at DESC LIMIT ?", (limit,))
        results = []
        for r in await c.fetchall():
            d = dict(r)
            if d.get("data"):
                try:
                    d["data"] = json.loads(d["data"])
                except (json.JSONDecodeError, ValueError):
                    pass
            results.append(d)
        return results

    # ── Stats ───────────────────────────────────────────────────────

    async def get_stats(self) -> dict:
        t = await self.conn.execute("SELECT COUNT(*) as c FROM targets")
        s = await self.conn.execute("SELECT COUNT(*) as c FROM scans")
        f = await self.conn.execute("SELECT COUNT(*) as c FROM findings")
        crit = await self.conn.execute("SELECT COUNT(*) as c FROM findings WHERE severity IN ('critical', 'high')")
        return {
            "targets": (await t.fetchone())["c"],
            "scans": (await s.fetchone())["c"],
            "findings": (await f.fetchone())["c"],
            "critical_high": (await crit.fetchone())["c"],
        }
