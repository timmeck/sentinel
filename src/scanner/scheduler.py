"""Scan Scheduler -- Recurring security scans on a schedule."""

import asyncio
from datetime import UTC, datetime

from src.utils.logger import get_logger

log = get_logger("scheduler")

INTERVAL_MAP = {
    "1h": 3600,
    "6h": 21600,
    "12h": 43200,
    "24h": 86400,
    "1d": 86400,
    "7d": 604800,
    "30d": 2592000,
}


class ScanScheduler:
    """Manages scheduled recurring scans."""

    def __init__(self, db, engine):
        self.db = db
        self.engine = engine
        self._running = False
        self._task = None

    async def ensure_table(self):
        await self.db.conn.execute("""
            CREATE TABLE IF NOT EXISTS schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                scan_type TEXT DEFAULT 'standard',
                interval_spec TEXT NOT NULL,
                interval_seconds INTEGER NOT NULL,
                enabled INTEGER DEFAULT 1,
                last_run_at TEXT,
                next_run_at TEXT,
                run_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
        """)
        await self.db.conn.execute("CREATE INDEX IF NOT EXISTS idx_sched_enabled ON schedules(enabled)")
        await self.db.conn.commit()

    async def add_schedule(self, target_url: str, interval: str, scan_type: str = "standard") -> dict:
        seconds = INTERVAL_MAP.get(interval)
        if not seconds:
            return {"error": f"Invalid interval. Options: {list(INTERVAL_MAP.keys())}"}

        now = datetime.now(UTC).isoformat()
        next_run = datetime.fromtimestamp(datetime.now(UTC).timestamp() + seconds, tz=UTC).isoformat()

        cursor = await self.db.conn.execute(
            "INSERT INTO schedules (target_url, scan_type, interval_spec, interval_seconds, "
            "next_run_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (target_url, scan_type, interval, seconds, next_run, now),
        )
        await self.db.conn.commit()
        return {"id": cursor.lastrowid, "url": target_url, "interval": interval, "scan_type": scan_type}

    async def list_schedules(self) -> list[dict]:
        c = await self.db.conn.execute("SELECT * FROM schedules ORDER BY created_at DESC")
        return [dict(r) for r in await c.fetchall()]

    async def delete_schedule(self, schedule_id: int) -> bool:
        cur = await self.db.conn.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
        await self.db.conn.commit()
        return cur.rowcount > 0

    async def toggle_schedule(self, schedule_id: int) -> dict | None:
        c = await self.db.conn.execute("SELECT * FROM schedules WHERE id = ?", (schedule_id,))
        row = await c.fetchone()
        if not row:
            return None
        new_state = 0 if row["enabled"] else 1
        await self.db.conn.execute("UPDATE schedules SET enabled = ? WHERE id = ?", (new_state, schedule_id))
        await self.db.conn.commit()
        return {"id": schedule_id, "enabled": bool(new_state)}

    async def start(self):
        """Start the scheduler loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        log.info("Scheduler started")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _loop(self):
        while self._running:
            try:
                now = datetime.now(UTC)
                c = await self.db.conn.execute(
                    "SELECT * FROM schedules WHERE enabled = 1 AND next_run_at <= ?", (now.isoformat(),)
                )
                due = await c.fetchall()

                for schedule in due:
                    s = dict(schedule)
                    log.info(f"Scheduled scan: {s['target_url']} ({s['scan_type']})")
                    try:
                        await self.engine.scan(s["target_url"], scan_type=s["scan_type"])
                    except Exception as e:
                        log.error(f"Scheduled scan failed: {e}")

                    # Update schedule
                    next_run = datetime.fromtimestamp(now.timestamp() + s["interval_seconds"], tz=UTC).isoformat()
                    await self.db.conn.execute(
                        "UPDATE schedules SET last_run_at = ?, next_run_at = ?, run_count = run_count + 1 WHERE id = ?",
                        (now.isoformat(), next_run, s["id"]),
                    )
                    await self.db.conn.commit()

            except Exception as e:
                log.error(f"Scheduler error: {e}")

            await asyncio.sleep(60)  # Check every minute
