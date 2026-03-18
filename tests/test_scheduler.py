"""Tests for scan scheduler."""

import asyncio

import pytest

from src.db.database import Database
from src.scanner.scheduler import INTERVAL_MAP, ScanScheduler


@pytest.fixture
def db(tmp_db_path):
    database = Database(db_path=tmp_db_path)
    asyncio.get_event_loop().run_until_complete(database.initialize())
    yield database
    asyncio.get_event_loop().run_until_complete(database.close())


def test_interval_map():
    assert INTERVAL_MAP["1h"] == 3600
    assert INTERVAL_MAP["24h"] == 86400
    assert INTERVAL_MAP["7d"] == 604800


def test_add_schedule(db):
    async def _test():
        sched = ScanScheduler(db, None)
        await sched.ensure_table()
        result = await sched.add_schedule("https://example.com", "24h", "standard")
        assert result["url"] == "https://example.com"
        assert result["interval"] == "24h"

        schedules = await sched.list_schedules()
        assert len(schedules) == 1

    asyncio.get_event_loop().run_until_complete(_test())


def test_add_schedule_invalid_interval(db):
    async def _test():
        sched = ScanScheduler(db, None)
        await sched.ensure_table()
        result = await sched.add_schedule("https://example.com", "99x")
        assert "error" in result

    asyncio.get_event_loop().run_until_complete(_test())


def test_delete_schedule(db):
    async def _test():
        sched = ScanScheduler(db, None)
        await sched.ensure_table()
        result = await sched.add_schedule("https://example.com", "1h")
        assert await sched.delete_schedule(result["id"])
        assert len(await sched.list_schedules()) == 0

    asyncio.get_event_loop().run_until_complete(_test())


def test_toggle_schedule(db):
    async def _test():
        sched = ScanScheduler(db, None)
        await sched.ensure_table()
        result = await sched.add_schedule("https://example.com", "1d")
        toggled = await sched.toggle_schedule(result["id"])
        assert not toggled["enabled"]
        toggled = await sched.toggle_schedule(result["id"])
        assert toggled["enabled"]

    asyncio.get_event_loop().run_until_complete(_test())
