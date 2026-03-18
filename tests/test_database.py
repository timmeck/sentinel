"""Tests for Sentinel database layer."""

import asyncio

import pytest

from src.db.database import Database


@pytest.fixture
def db(tmp_db_path):
    database = Database(db_path=tmp_db_path)
    asyncio.get_event_loop().run_until_complete(database.initialize())
    yield database
    asyncio.get_event_loop().run_until_complete(database.close())


def test_create_target(db):
    async def _test():
        target = await db.create_target("https://example.com", name="Example")
        assert target["url"] == "https://example.com"
        assert target["name"] == "Example"
        assert target["target_type"] == "web"
        assert target["scan_count"] == 0

    asyncio.get_event_loop().run_until_complete(_test())


def test_get_target_by_url(db):
    async def _test():
        await db.create_target("https://test.com", name="Test")
        found = await db.get_target_by_url("https://test.com")
        assert found is not None
        assert found["name"] == "Test"
        not_found = await db.get_target_by_url("https://nope.com")
        assert not_found is None

    asyncio.get_event_loop().run_until_complete(_test())


def test_list_targets(db):
    async def _test():
        await db.create_target("https://a.com")
        await db.create_target("https://b.com")
        targets = await db.list_targets()
        assert len(targets) == 2

    asyncio.get_event_loop().run_until_complete(_test())


def test_delete_target(db):
    async def _test():
        t = await db.create_target("https://del.com")
        assert await db.delete_target(t["id"])
        assert await db.get_target(t["id"]) is None

    asyncio.get_event_loop().run_until_complete(_test())


def test_create_scan(db):
    async def _test():
        t = await db.create_target("https://example.com")
        scan = await db.create_scan(t["id"], scan_type="full")
        assert scan["status"] == "running"
        assert scan["scan_type"] == "full"
        # Target scan count incremented
        target = await db.get_target(t["id"])
        assert target["scan_count"] == 1

    asyncio.get_event_loop().run_until_complete(_test())


def test_list_scans(db):
    async def _test():
        t = await db.create_target("https://example.com")
        await db.create_scan(t["id"], "quick")
        await db.create_scan(t["id"], "full")
        scans = await db.list_scans(target_id=t["id"])
        assert len(scans) == 2
        all_scans = await db.list_scans()
        assert len(all_scans) == 2

    asyncio.get_event_loop().run_until_complete(_test())


def test_update_scan(db):
    async def _test():
        t = await db.create_target("https://example.com")
        scan = await db.create_scan(t["id"])
        await db.update_scan(scan["id"], status="completed", score=85.0)
        updated = await db.get_scan(scan["id"])
        assert updated["status"] == "completed"
        assert updated["score"] == 85.0

    asyncio.get_event_loop().run_until_complete(_test())


def test_delete_scan(db):
    async def _test():
        t = await db.create_target("https://example.com")
        s = await db.create_scan(t["id"])
        assert await db.delete_scan(s["id"])
        assert await db.get_scan(s["id"]) is None

    asyncio.get_event_loop().run_until_complete(_test())


def test_add_finding(db):
    async def _test():
        t = await db.create_target("https://example.com")
        s = await db.create_scan(t["id"])
        f = await db.add_finding(
            scan_id=s["id"],
            severity="high",
            category="headers",
            title="Missing HSTS",
            description="No HSTS header found",
            recommendation="Add HSTS header",
            cwe_id="CWE-319",
        )
        assert f["severity"] == "high"
        assert f["title"] == "Missing HSTS"
        # Findings count updated
        scan = await db.get_scan(s["id"])
        assert scan["findings_count"] == 1

    asyncio.get_event_loop().run_until_complete(_test())


def test_get_findings_sorted_by_severity(db):
    async def _test():
        t = await db.create_target("https://example.com")
        s = await db.create_scan(t["id"])
        await db.add_finding(s["id"], "low", "headers", "Low issue", "desc")
        await db.add_finding(s["id"], "critical", "ssl", "Critical issue", "desc")
        await db.add_finding(s["id"], "medium", "cookies", "Medium issue", "desc")
        findings = await db.get_findings(s["id"])
        assert findings[0]["severity"] == "critical"
        assert findings[1]["severity"] == "medium"
        assert findings[2]["severity"] == "low"

    asyncio.get_event_loop().run_until_complete(_test())


def test_search_findings_fallback(db):
    async def _test():
        t = await db.create_target("https://example.com")
        s = await db.create_scan(t["id"])
        await db.add_finding(s["id"], "high", "ssl", "Certificate expired", "The SSL certificate has expired")
        await db.add_finding(s["id"], "low", "headers", "Server header", "Server version exposed")
        results = await db.search_findings("certificate", limit=5)
        assert len(results) >= 1
        assert any(
            "certificate" in r.get("title", "").lower() or "certificate" in r.get("description", "").lower()
            for r in results
        )

    asyncio.get_event_loop().run_until_complete(_test())


def test_log_event(db):
    async def _test():
        await db.log_event("test_event", "Test message", data={"key": "value"})
        activity = await db.get_activity(limit=1)
        assert len(activity) == 1
        assert activity[0]["event_type"] == "test_event"
        assert activity[0]["data"]["key"] == "value"

    asyncio.get_event_loop().run_until_complete(_test())


def test_get_stats(db):
    async def _test():
        stats = await db.get_stats()
        assert stats["targets"] == 0
        assert stats["scans"] == 0
        assert stats["findings"] == 0
        assert stats["critical_high"] == 0

        t = await db.create_target("https://example.com")
        s = await db.create_scan(t["id"])
        await db.add_finding(s["id"], "high", "ssl", "Issue", "Desc")
        await db.add_finding(s["id"], "info", "tech", "Tech", "Desc")

        stats = await db.get_stats()
        assert stats["targets"] == 1
        assert stats["scans"] == 1
        assert stats["findings"] == 2
        assert stats["critical_high"] == 1

    asyncio.get_event_loop().run_until_complete(_test())


def test_cascade_delete_target(db):
    async def _test():
        t = await db.create_target("https://example.com")
        s = await db.create_scan(t["id"])
        await db.add_finding(s["id"], "medium", "headers", "Issue", "Desc")
        await db.delete_target(t["id"])
        # Everything should be gone
        assert await db.get_target(t["id"]) is None
        scans = await db.list_scans(target_id=t["id"])
        assert len(scans) == 0

    asyncio.get_event_loop().run_until_complete(_test())
