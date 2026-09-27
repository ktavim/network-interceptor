"""The queue, lease and event SQL against a real Postgres. Set TEST_DATABASE_URL to run."""
import asyncio
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from dotenv import dotenv_values
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from core.db import AppRow, Base, FindingRow, ScanEventRow, ScanRow
from core.events import emit_event_now
from worker.job import LEASE_LOST, SHUTDOWN, USER, Job, run_scan_job
from worker.queue import ClaimedScan, claim_next, finish, heartbeat, reap_stale

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")
DEV_DATABASE_URL = os.environ.get("DATABASE_URL") or dotenv_values().get("DATABASE_URL")

pytestmark = [
    pytest.mark.skipif(not TEST_DATABASE_URL, reason="TEST_DATABASE_URL not set"),
    # The fixture truncates every table.
    pytest.mark.skipif(
        TEST_DATABASE_URL is not None and TEST_DATABASE_URL == DEV_DATABASE_URL,
        reason="TEST_DATABASE_URL is DATABASE_URL",
    ),
]

STALE = timedelta(minutes=5)


@pytest.fixture
async def factory():
    engine = create_async_engine(TEST_DATABASE_URL)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("TRUNCATE apps, scans, scan_events, findings, urls, submissions CASCADE"))
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _add_scan(factory, status="queued", **values) -> str:
    app_id, scan_id = uuid.uuid4().hex, uuid.uuid4().hex
    async with factory() as session:
        session.add(AppRow(id=app_id, name="app", url="http://x", owner_ad_group="g"))
        session.add(ScanRow(
            id=scan_id, app_id=app_id, name="app", url="http://x",
            status=status, started_by="test", **values,
        ))
        await session.commit()
    return scan_id


async def _scan(factory, scan_id) -> ScanRow:
    async with factory() as session:
        return await session.get(ScanRow, scan_id)


async def _events(factory, scan_id) -> list:
    async with factory() as session:
        rows = await session.execute(
            select(ScanEventRow).where(ScanEventRow.scan_id == scan_id).order_by(ScanEventRow.seq)
        )
        return [(r.seq, r.type, r.payload) for r in rows.scalars()]


async def test_concurrent_emits_get_contiguous_seqs(factory):
    scan_id = await _add_scan(factory)
    await asyncio.gather(*(emit_event_now(factory, scan_id, "page_visited", {}) for _ in range(20)))
    assert [seq for seq, _, _ in await _events(factory, scan_id)] == list(range(20))


async def test_one_of_two_concurrent_claims_wins(factory):
    scan_id = await _add_scan(factory)
    claims = await asyncio.gather(claim_next(factory, "w1"), claim_next(factory, "w2"))
    assert [c.id for c in claims if c] == [scan_id]
    scan = await _scan(factory, scan_id)
    assert scan.status == "running" and scan.heartbeat_at is not None


async def test_claims_oldest_first_and_skips_other_statuses(factory):
    await _add_scan(factory, status="cancelled", started_at=_now() - timedelta(hours=2))
    older = await _add_scan(factory, started_at=_now() - timedelta(hours=1))
    await _add_scan(factory, started_at=_now())
    assert (await claim_next(factory, "w")).id == older


async def test_reaper_ends_stale_scans_of_other_workers(factory):
    stale = _now() - STALE
    lost = await _add_scan(factory, status="running", heartbeat_at=stale)
    cancelling = await _add_scan(factory, status="running", heartbeat_at=stale, cancel_requested_at=stale)
    mine = await _add_scan(factory, status="running", heartbeat_at=stale)
    fresh = await _add_scan(factory, status="running", heartbeat_at=_now())

    assert sorted(await reap_stale(factory, [mine])) == sorted([lost, cancelling])

    assert ((await _scan(factory, lost)).status, (await _scan(factory, lost)).error) == ("failed", "worker lost")
    assert (await _scan(factory, cancelling)).status == "cancelled"
    assert (await _scan(factory, mine)).status == "running"
    assert (await _scan(factory, fresh)).status == "running"
    assert await _events(factory, lost) == [(0, "scan_failed", {"error": "worker lost"})]
    assert await _events(factory, cancelling) == [(0, "scan_failed", {"reason": "cancelled"})]
    assert await _events(factory, mine) == []


async def test_heartbeat_refreshes_running_scans_and_reports_cancels(factory):
    stale = _now() - STALE
    running = await _add_scan(factory, status="running", heartbeat_at=stale)
    cancelling = await _add_scan(factory, status="running", heartbeat_at=stale, cancel_requested_at=_now())
    ended = await _add_scan(factory, status="failed")

    held = await heartbeat(factory, [running, cancelling, ended])

    assert set(held) == {running, cancelling}
    assert held[running] is None and held[cancelling] is not None
    assert (await _scan(factory, running)).heartbeat_at > stale


async def test_finish_ends_a_running_scan_once(factory):
    scan_id = await _add_scan(factory, status="running")
    async with factory() as session:
        assert await finish(session, scan_id, "completed")
        assert not await finish(session, scan_id, "failed")
        await session.commit()
    assert (await _scan(factory, scan_id)).status == "completed"


class _FakeMapper:
    """Stands in for the crawler; map_website returns `result`, or blocks when it is None."""

    result = None
    started: asyncio.Event

    def __init__(self, config, on_event=None):
        pass

    async def initialize(self):
        pass

    async def map_website(self):
        _FakeMapper.started.set()
        if _FakeMapper.result is None:
            await asyncio.sleep(3600)
        return _FakeMapper.result

    async def cleanup(self):
        pass


@pytest.fixture
def fake_mapper(monkeypatch):
    _FakeMapper.result = None
    _FakeMapper.started = asyncio.Event()
    monkeypatch.setattr("worker.job.Mapper", _FakeMapper)
    return _FakeMapper


def _start_job(factory, scan_id, make_config) -> Job:
    job = Job(ClaimedScan(scan_id, "http://x", None))
    job.task = asyncio.create_task(run_scan_job(job, make_config(), factory))
    return job


@pytest.mark.parametrize("reason, status, error, events", [
    (USER, "cancelled", "cancelled", [(0, "scan_failed", {"reason": "cancelled"})]),
    (SHUTDOWN, "failed", "worker shut down", [(0, "scan_failed", {"error": "worker shut down"})]),
    (LEASE_LOST, "running", None, []),
])
async def test_cancelled_job_records_its_reason(factory, fake_mapper, make_config, reason, status, error, events):
    scan_id = await _add_scan(factory, status="running")
    job = _start_job(factory, scan_id, make_config)
    await fake_mapper.started.wait()

    job.request_cancel(reason)
    await asyncio.wait({job.task})

    assert job.task.cancelled()
    scan = await _scan(factory, scan_id)
    assert (scan.status, scan.error) == (status, error)
    assert await _events(factory, scan_id) == events


async def test_completed_job_records_findings_and_events(factory, fake_mapper, make_config):
    scan_id = await _add_scan(factory, status="running")
    fake_mapper.result = {
        "pages_crawled": 3,
        "external_services": [{
            "scheme": "https", "host": "a.example", "port": 443,
            "authentication": "ntlm", "request_count": 1, "ips": ["10.0.0.1"],
            "urls": [{"method": "GET", "url": "https://a.example/x", "status": 401,
                      "authentication": "ntlm", "page_url": "http://x"}],
            "evidence_index": 0,
        }],
    }
    job = _start_job(factory, scan_id, make_config)
    await asyncio.wait({job.task})

    assert job.task.exception() is None
    scan = await _scan(factory, scan_id)
    assert (scan.status, scan.pages_crawled) == ("completed", 3)
    async with factory() as session:
        findings = (await session.execute(select(FindingRow).where(FindingRow.scan_id == scan_id))).scalars().all()
    assert [(f.host, f.severity) for f in findings] == [("a.example", "blocker")]
    assert findings[0].evidence_url_id is not None
    types = [t for _, t, _ in await _events(factory, scan_id)]
    assert types == ["blocker_found", "scan_completed"]


async def test_job_that_raises_records_failure(factory, fake_mapper, make_config, monkeypatch):
    scan_id = await _add_scan(factory, status="running")

    async def boom(self):
        raise RuntimeError("navigation exploded")

    monkeypatch.setattr(_FakeMapper, "map_website", boom)
    job = _start_job(factory, scan_id, make_config)
    await asyncio.wait({job.task})

    assert job.task.exception() is None
    scan = await _scan(factory, scan_id)
    assert (scan.status, scan.error) == ("failed", "RuntimeError: navigation exploded")
    assert [t for _, t, _ in await _events(factory, scan_id)] == ["scan_failed"]
