"""Tests for the scan diff API endpoint and comparison logic."""

import asyncio

import pytest

from src.db.database import Database
from src.scanner.diff import compare_scans


@pytest.fixture
def db(tmp_db_path):
    database = Database(db_path=tmp_db_path)
    asyncio.get_event_loop().run_until_complete(database.initialize())
    yield database
    asyncio.get_event_loop().run_until_complete(database.close())


def test_diff_structured_output(db):
    """Diff returns added/removed/changed structure."""

    async def _test():
        t = await db.create_target("https://example.com")

        # Scan 1: 3 findings
        s1 = await db.create_scan(t["id"], "full")
        await db.add_finding(s1["id"], "high", "headers", "Missing HSTS", "No HSTS header")
        await db.add_finding(s1["id"], "medium", "headers", "Missing CSP", "No CSP header")
        await db.add_finding(s1["id"], "low", "cookies", "Missing SameSite", "No SameSite")
        await db.update_scan(s1["id"], status="completed", score=78.0)

        # Scan 2: HSTS persists, CSP resolved, new cookie finding
        s2 = await db.create_scan(t["id"], "full")
        await db.add_finding(s2["id"], "high", "headers", "Missing HSTS", "No HSTS header")
        await db.add_finding(s2["id"], "medium", "cookies", "Missing Secure flag", "No Secure flag")
        await db.update_scan(s2["id"], status="completed", score=80.0)

        result = await compare_scans(db, s1["id"], s2["id"])

        # new_findings = findings in s2 not in s1
        new_titles = [f["title"] for f in result["new_findings"]]
        assert "Missing Secure flag" in new_titles

        # resolved_findings = findings in s1 not in s2
        resolved_titles = [f["title"] for f in result["resolved_findings"]]
        assert "Missing CSP" in resolved_titles
        assert "Missing SameSite" in resolved_titles

        # persistent = in both
        persistent_titles = [f["title"] for f in result["persistent_findings"]]
        assert "Missing HSTS" in persistent_titles

        # Score improved
        assert result["score_change"] == 2.0

    asyncio.get_event_loop().run_until_complete(_test())


def test_diff_identical_scans(db):
    """Identical scans produce no new/resolved findings."""

    async def _test():
        t = await db.create_target("https://example.com")

        s1 = await db.create_scan(t["id"], "full")
        await db.add_finding(s1["id"], "high", "headers", "Missing HSTS", "desc")
        await db.update_scan(s1["id"], status="completed", score=85.0)

        s2 = await db.create_scan(t["id"], "full")
        await db.add_finding(s2["id"], "high", "headers", "Missing HSTS", "desc")
        await db.update_scan(s2["id"], status="completed", score=85.0)

        result = await compare_scans(db, s1["id"], s2["id"])
        assert len(result["new_findings"]) == 0
        assert len(result["resolved_findings"]) == 0
        assert len(result["persistent_findings"]) == 1
        assert result["score_change"] == 0.0

    asyncio.get_event_loop().run_until_complete(_test())


def test_diff_empty_to_findings(db):
    """Comparing empty scan to one with findings shows all as new."""

    async def _test():
        t = await db.create_target("https://example.com")

        s1 = await db.create_scan(t["id"], "full")
        await db.update_scan(s1["id"], status="completed", score=100.0)

        s2 = await db.create_scan(t["id"], "full")
        await db.add_finding(s2["id"], "critical", "ssl", "Expired cert", "desc")
        await db.add_finding(s2["id"], "high", "headers", "Missing HSTS", "desc")
        await db.update_scan(s2["id"], status="completed", score=60.0)

        result = await compare_scans(db, s1["id"], s2["id"])
        assert len(result["new_findings"]) == 2
        assert len(result["resolved_findings"]) == 0
        assert result["score_change"] == -40.0

    asyncio.get_event_loop().run_until_complete(_test())


def test_diff_findings_to_empty(db):
    """Comparing scan with findings to empty shows all resolved."""

    async def _test():
        t = await db.create_target("https://example.com")

        s1 = await db.create_scan(t["id"], "full")
        await db.add_finding(s1["id"], "high", "headers", "Missing HSTS", "desc")
        await db.add_finding(s1["id"], "medium", "headers", "Missing CSP", "desc")
        await db.update_scan(s1["id"], status="completed", score=80.0)

        s2 = await db.create_scan(t["id"], "full")
        await db.update_scan(s2["id"], status="completed", score=100.0)

        result = await compare_scans(db, s1["id"], s2["id"])
        assert len(result["new_findings"]) == 0
        assert len(result["resolved_findings"]) == 2
        assert result["score_change"] == 20.0
        assert "improved" in result["summary"].lower()

    asyncio.get_event_loop().run_until_complete(_test())
