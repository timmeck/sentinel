"""Tests for scan diff/comparison."""

import asyncio
import pytest
from src.db.database import Database
from src.scanner.diff import compare_scans, _fingerprint


@pytest.fixture
def db(tmp_db_path):
    database = Database(db_path=tmp_db_path)
    asyncio.get_event_loop().run_until_complete(database.initialize())
    yield database
    asyncio.get_event_loop().run_until_complete(database.close())


def test_fingerprint():
    f1 = {"category": "headers", "title": "Missing HSTS"}
    f2 = {"category": "headers", "title": "Missing CSP"}
    assert _fingerprint(f1) != _fingerprint(f2)
    assert _fingerprint(f1) == _fingerprint({"category": "headers", "title": "Missing HSTS"})


def test_compare_scans(db):
    async def _test():
        t = await db.create_target("https://example.com")

        # Old scan: 2 findings
        s1 = await db.create_scan(t["id"], "full")
        await db.add_finding(s1["id"], "high", "headers", "Missing HSTS", "desc")
        await db.add_finding(s1["id"], "medium", "headers", "Missing CSP", "desc")
        await db.update_scan(s1["id"], status="completed", score=80.0)

        # New scan: 1 old finding resolved, 1 new finding
        s2 = await db.create_scan(t["id"], "full")
        await db.add_finding(s2["id"], "high", "headers", "Missing HSTS", "desc")
        await db.add_finding(s2["id"], "low", "cookies", "Missing Secure flag", "desc")
        await db.update_scan(s2["id"], status="completed", score=83.0)

        result = await compare_scans(db, s1["id"], s2["id"])

        assert result["score_change"] == 3.0
        assert len(result["new_findings"]) == 1  # cookies finding
        assert len(result["resolved_findings"]) == 1  # CSP resolved
        assert len(result["persistent_findings"]) == 1  # HSTS persists
        assert "improved" in result["summary"].lower()
    asyncio.get_event_loop().run_until_complete(_test())


def test_compare_nonexistent_scan(db):
    async def _test():
        result = await compare_scans(db, 999, 998)
        assert "error" in result
    asyncio.get_event_loop().run_until_complete(_test())
