"""Tests for report export."""

import asyncio
import json
import pytest
from src.db.database import Database
from src.scanner.export import export_json, export_html


@pytest.fixture
def db(tmp_db_path):
    database = Database(db_path=tmp_db_path)
    asyncio.get_event_loop().run_until_complete(database.initialize())
    yield database
    asyncio.get_event_loop().run_until_complete(database.close())


def test_export_json(db):
    async def _test():
        t = await db.create_target("https://example.com", name="Example")
        s = await db.create_scan(t["id"], "full")
        await db.add_finding(s["id"], "high", "ssl", "Weak cipher", "desc", recommendation="Fix it")
        await db.update_scan(s["id"], status="completed", score=85.0)

        data = await export_json(db, s["id"])
        report = json.loads(data)

        assert report["target"]["url"] == "https://example.com"
        assert report["scan"]["score"] == 85.0
        assert report["summary"]["total"] == 1
        assert report["summary"]["high"] == 1
        assert len(report["findings"]) == 1
        assert report["findings"][0]["title"] == "Weak cipher"
    asyncio.get_event_loop().run_until_complete(_test())


def test_export_html(db):
    async def _test():
        t = await db.create_target("https://example.com")
        s = await db.create_scan(t["id"], "quick")
        await db.add_finding(s["id"], "critical", "ssl", "Cert expired", "The cert is expired")
        await db.update_scan(s["id"], status="completed", score=75.0)

        html = await export_html(db, s["id"])

        assert "<!DOCTYPE html>" in html
        assert "example.com" in html
        assert "75" in html
        assert "Cert expired" in html
        assert "CRITICAL" in html
    asyncio.get_event_loop().run_until_complete(_test())


def test_export_nonexistent_scan(db):
    async def _test():
        data = await export_json(db, 999)
        assert "error" in data

        html = await export_html(db, 999)
        assert "not found" in html.lower()
    asyncio.get_event_loop().run_until_complete(_test())
