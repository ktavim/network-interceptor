"""The job queue, lease, finalize and event SQL against a real Postgres. Set TEST_DATABASE_URL to run."""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from core.db import AppRow, ScanEventRow, ScanJobRow, ScanRow, ServiceFindingRow, ServiceRow, UrlRow
from core.enums import JobStatus, Scanner
from core.events import emit_event_now
from core.jobs import ClaimedJob, cancel, claim_next, finish, heartbeat, reap_stale, release
from core.translate import services_to_rows
from worker.job import LEASE_LOST, SHUTDOWN, USER, Job, run_scan_job

STALE = timedelta(minutes=5)

INTERCEPTOR = Scanner.interceptor
TRACER = Scanner.tracer


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _add_scan(factory, status="queued", *, cancel_requested_at=None, tracer=None, **job) -> str:
    """A scan on an app of its own, with an interceptor job in the scan's status.

    `job` overrides that job's columns. `tracer`, the column values of a tracer
    job, gives the scan a second job. Returns the scan id.
    """
    app_id, scan_id = uuid.uuid4().hex, uuid.uuid4().hex
    jobs = {INTERCEPTOR: job}
    if tracer is not None:
        jobs[TRACER] = tracer
    async with factory() as session:
        session.add(AppRow(id=app_id, name="app", url="http://x", owner_ad_group="g"))
        session.add(ScanRow(
            id=scan_id, app_id=app_id, name="app", url="http://x",
            status=status, started_by="test", cancel_requested_at=cancel_requested_at,
        ))
        for scanner, values in jobs.items():
            session.add(ScanJobRow(**{
                "id": uuid.uuid4().hex, "scan_id": scan_id, "scanner": scanner.value,
                "status": status, "settings": {}, **values,
            }))
        await session.commit()
    return scan_id


async def _scan(factory, scan_id) -> ScanRow:
    async with factory() as session:
        return await session.get(ScanRow, scan_id)


async def _job(factory, scan_id, scanner=INTERCEPTOR) -> ScanJobRow:
    async with factory() as session:
        return (await session.execute(
            select(ScanJobRow).where(ScanJobRow.scan_id == scan_id, ScanJobRow.scanner == scanner.value)
        )).scalar_one()


async def _events(factory, scan_id) -> list:
    async with factory() as session:
        rows = await session.execute(
            select(ScanEventRow).where(ScanEventRow.scan_id == scan_id).order_by(ScanEventRow.seq)
        )
        return [(r.seq, r.type, r.payload) for r in rows.scalars()]


async def _event_types(factory, scan_id) -> list:
    return [event_type for _, event_type, _ in await _events(factory, scan_id)]


async def _services(factory, scan_id) -> list:
    async with factory() as session:
        return (await session.execute(
            select(ServiceRow).where(ServiceRow.scan_id == scan_id).order_by(ServiceRow.host)
        )).scalars().all()


async def _findings(factory, service_id) -> dict:
    """{scanner: (auth_method, url_count)} for a service."""
    async with factory() as session:
        rows = (await session.execute(
            select(ServiceFindingRow).where(ServiceFindingRow.service_id == service_id)
        )).scalars().all()
        return {r.scanner: (r.auth_method, r.url_count) for r in rows}


def _rows(scan_id, scanner, host, auth_method, urls=1, ips=None) -> dict:
    """One service and its urls as `scanner` alone sees them: finish()'s results."""
    service_rows, url_rows = services_to_rows(scan_id, [{
        "scheme": "https", "host": host, "port": 443, "authentication": auth_method, "ips": ips,
        "urls": [
            {"method": "GET", "url": f"https://{host}/{i}", "status": 200, "authentication": auth_method}
            for i in range(urls)
        ],
        "evidence_index": 0,
    }])
    for row in url_rows:
        row["scanner"] = scanner.value
    return {"service_rows": service_rows, "url_rows": url_rows}


async def _finish(factory, scan_id, scanner, status, **values) -> bool:
    job = await _job(factory, scan_id, scanner)
    async with factory() as session:
        ended = await finish(session, job.id, status, **values)
        await session.commit()
    return ended


async def _cancel(factory, scan_id) -> None:
    async with factory() as session:
        await cancel(session, scan_id)
        await session.commit()


async def test_concurrent_emits_get_contiguous_seqs(factory):
    scan_id = await _add_scan(factory)
    await asyncio.gather(*(emit_event_now(factory, scan_id, "page_visited", {}) for _ in range(20)))
    assert [seq for seq, _, _ in await _events(factory, scan_id)] == list(range(20))


async def test_one_of_two_concurrent_claims_wins(factory):
    scan_id = await _add_scan(factory)
    claims = await asyncio.gather(
        claim_next(factory, INTERCEPTOR, "w1"), claim_next(factory, INTERCEPTOR, "w2")
    )
    won = [c for c in claims if c]
    job = await _job(factory, scan_id)
    assert [(c.id, c.scan_id, c.url) for c in won] == [(job.id, scan_id, "http://x")]
    assert (job.status, job.attempts) == ("running", 1) and job.heartbeat_at is not None
    assert (await _scan(factory, scan_id)).status == "running"
    assert await _events(factory, scan_id) == [(0, "job_started", {"scanner": "interceptor"})]


async def test_claims_oldest_first_and_skips_other_statuses(factory):
    await _add_scan(factory, status="cancelled", created_at=_now() - timedelta(hours=2))
    older = await _add_scan(factory, created_at=_now() - timedelta(hours=1))
    await _add_scan(factory, created_at=_now())
    assert (await claim_next(factory, INTERCEPTOR, "w")).scan_id == older


async def test_claims_only_jobs_of_its_scanner(factory):
    scan_id = await _add_scan(factory, tracer={"settings": {"max_pages": 1}})
    claim = await claim_next(factory, TRACER, "w")
    assert (claim.scanner, claim.settings) == (TRACER, {"max_pages": 1})
    # The interceptor job is still queued, and not a tracer worker's to take.
    assert await claim_next(factory, TRACER, "w") is None
    assert (await _job(factory, scan_id)).status == "queued"
    assert (await _scan(factory, scan_id)).status == "running"


async def test_release_requeues_a_claimed_job(factory):
    scan_id = await _add_scan(factory)
    claim = await claim_next(factory, INTERCEPTOR, "w1")
    await release(factory, claim.id)
    job = await _job(factory, scan_id)
    assert (job.status, job.worker_id, job.heartbeat_at) == ("queued", None, None)
    assert (await _scan(factory, scan_id)).status == "queued"
    assert (await claim_next(factory, INTERCEPTOR, "w2")).id == claim.id


async def test_release_leaves_the_scan_running_while_another_job_runs(factory):
    scan_id = await _add_scan(factory, tracer={})
    await claim_next(factory, TRACER, "w1")
    claim = await claim_next(factory, INTERCEPTOR, "w2")
    await release(factory, claim.id)
    assert (await _job(factory, scan_id)).status == "queued"
    assert (await _scan(factory, scan_id)).status == "running"


async def test_reaper_ends_stale_jobs_of_other_workers(factory):
    stale = _now() - STALE
    lost = await _add_scan(factory, status="running", heartbeat_at=stale)
    cancelling = await _add_scan(factory, status="running", heartbeat_at=stale, cancel_requested_at=stale)
    mine = await _add_scan(factory, status="running", heartbeat_at=stale)
    fresh = await _add_scan(factory, status="running", heartbeat_at=_now())
    job_id = {scan_id: (await _job(factory, scan_id)).id for scan_id in (lost, cancelling, mine, fresh)}

    reaped = await reap_stale(factory, [job_id[mine]])

    assert sorted(reaped) == sorted([job_id[lost], job_id[cancelling]])
    job = await _job(factory, lost)
    assert (job.status, job.error) == ("failed", "worker lost")
    scan = await _scan(factory, lost)
    assert (scan.status, scan.error) == ("failed", "worker lost") and scan.completed_at is not None
    assert (await _job(factory, cancelling)).status == "cancelled"
    assert (await _scan(factory, cancelling)).status == "cancelled"
    assert (await _scan(factory, mine)).status == "running"
    assert (await _scan(factory, fresh)).status == "running"
    assert await _events(factory, lost) == [
        (0, "job_failed", {"scanner": "interceptor", "error": "worker lost"}),
        (1, "scan_failed", {"error": "worker lost"}),
    ]
    assert await _events(factory, cancelling) == [
        (0, "job_failed", {"scanner": "interceptor", "error": "cancelled"}),
        (1, "scan_failed", {"reason": "cancelled"}),
    ]
    assert await _events(factory, mine) == []


async def test_reaped_job_leaves_the_scan_to_its_other_job(factory):
    stale = _now() - STALE
    scan_id = await _add_scan(factory, status="running", heartbeat_at=stale, tracer={"heartbeat_at": _now()})

    assert await reap_stale(factory, []) == [(await _job(factory, scan_id)).id]

    assert (await _scan(factory, scan_id)).status == "running"
    assert await _event_types(factory, scan_id) == ["job_failed"]
    # The scan ends with the tracer job: one scanner completed, one failed.
    assert await _finish(factory, scan_id, TRACER, JobStatus.completed)
    scan = await _scan(factory, scan_id)
    assert (scan.status, scan.error) == ("partial", "interceptor: worker lost")


async def test_heartbeat_refreshes_running_jobs_and_reports_cancels(factory):
    stale = _now() - STALE
    running = await _add_scan(factory, status="running", heartbeat_at=stale)
    cancelling = await _add_scan(factory, status="running", heartbeat_at=stale, cancel_requested_at=_now())
    ended = await _add_scan(factory, status="failed")
    job_id = {scan_id: (await _job(factory, scan_id)).id for scan_id in (running, cancelling, ended)}

    held = await heartbeat(factory, list(job_id.values()))

    assert set(held) == {job_id[running], job_id[cancelling]}
    assert held[job_id[running]] is None and held[job_id[cancelling]] is not None
    assert (await _job(factory, running)).heartbeat_at > stale


async def test_finish_ends_a_running_job_once(factory):
    scan_id = await _add_scan(factory, status="running")
    assert await _finish(factory, scan_id, INTERCEPTOR, JobStatus.completed)
    assert not await _finish(factory, scan_id, INTERCEPTOR, JobStatus.failed, error="late")
    job = await _job(factory, scan_id)
    assert (job.status, job.error) == ("completed", None) and job.completed_at is not None
    assert (await _scan(factory, scan_id)).status == "completed"
    assert await _event_types(factory, scan_id) == ["job_completed", "scan_completed"]


async def test_scan_ends_with_the_last_of_its_jobs(factory):
    scan_id = await _add_scan(factory, status="running", tracer={})

    await _finish(factory, scan_id, INTERCEPTOR, JobStatus.completed, pages_crawled=2,
                  **_rows(scan_id, INTERCEPTOR, "a.example", "basic"))

    # The first scanner's services show while the other still runs.
    assert (await _scan(factory, scan_id)).status == "running"
    assert [(s.host, s.severity) for s in await _services(factory, scan_id)] == [("a.example", "blocker")]
    assert await _events(factory, scan_id) == [
        (0, "job_completed", {"scanner": "interceptor", "services": 1}),
    ]

    await _finish(factory, scan_id, TRACER, JobStatus.completed,
                  **_rows(scan_id, TRACER, "b.example", "unauthenticated"))

    scan = await _scan(factory, scan_id)
    assert (scan.status, scan.error) == ("completed", None) and scan.completed_at is not None
    events = await _events(factory, scan_id)
    assert [t for _, t, _ in events] == ["job_completed", "job_completed", "blocker_found", "scan_completed"]
    assert events[2][2] == {"scheme": "https", "host": "a.example", "port": 443, "auth_method": "basic"}
    terminal = events[3][2]
    assert terminal.pop("duration_ms") >= 0
    assert terminal == {"services": 2, "blockers": 1, "partial": False, "failed_scanners": []}


async def test_two_scanners_findings_for_an_origin_merge_into_one_service(factory):
    scan_id = await _add_scan(factory, status="running", tracer={})
    observed = _rows(scan_id, INTERCEPTOR, "api.example", "bearer", urls=2, ips=["10.0.0.1"])
    # The token-API case: the browser used a bearer token, the anonymous probe got a bare 401.
    probed = _rows(scan_id, TRACER, "api.example", "unknown", ips=["10.0.0.1", "10.0.0.2"])

    await _finish(factory, scan_id, TRACER, JobStatus.completed, **probed)
    [service] = await _services(factory, scan_id)
    assert (service.auth_method, service.severity, service.request_count) == ("unknown", "review", 1)

    await _finish(factory, scan_id, INTERCEPTOR, JobStatus.completed, **observed)

    [service] = await _services(factory, scan_id)
    assert (service.auth_method, service.severity) == ("bearer", "cleared")
    assert service.evidence_url_id == observed["service_rows"][0]["evidence_url_id"]
    assert service.request_count == 3
    assert service.ips == ["10.0.0.1", "10.0.0.2"]
    assert await _findings(factory, service.id) == {"interceptor": ("bearer", 2), "tracer": ("unknown", 1)}
    async with factory() as session:
        urls = (await session.execute(select(UrlRow).where(UrlRow.service_id == service.id))).scalars().all()
    assert sorted(u.scanner for u in urls) == ["interceptor", "interceptor", "tracer"]
    # Cleared by the merge, so not announced as a blocker or counted as one.
    assert (await _events(factory, scan_id))[-1][2]["blockers"] == 0


@pytest.mark.parametrize("statuses, scan_status, error, terminal", [
    (
        (JobStatus.completed, JobStatus.failed), "partial", "tracer: boom",
        ("scan_completed", {"services": 1, "blockers": 0, "partial": True, "failed_scanners": ["tracer"]}),
    ),
    (
        (JobStatus.failed, JobStatus.failed), "failed", "interceptor: boom; tracer: boom",
        ("scan_failed", {"error": "interceptor: boom; tracer: boom"}),
    ),
])
async def test_scan_with_a_failed_job_ends_partial_or_failed(factory, statuses, scan_status, error, terminal):
    scan_id = await _add_scan(factory, status="running", tracer={})
    for scanner, status in zip((INTERCEPTOR, TRACER), statuses):
        if status is JobStatus.completed:
            await _finish(factory, scan_id, scanner, status, **_rows(scan_id, scanner, "a.example", "oauth"))
        else:
            await _finish(factory, scan_id, scanner, status, error="boom")

    scan = await _scan(factory, scan_id)
    assert (scan.status, scan.error) == (scan_status, error)
    _, event_type, payload = (await _events(factory, scan_id))[-1]
    payload.pop("duration_ms", None)
    assert (event_type, payload) == terminal


async def test_cancel_ends_a_queued_scan_at_once(factory):
    scan_id = await _add_scan(factory)
    await _cancel(factory, scan_id)
    job = await _job(factory, scan_id)
    assert (job.status, job.error) == ("cancelled", "cancelled")
    scan = await _scan(factory, scan_id)
    assert (scan.status, scan.error) == ("cancelled", "cancelled") and scan.completed_at is not None
    assert await _events(factory, scan_id) == [
        (0, "job_failed", {"scanner": "interceptor", "error": "cancelled"}),
        (1, "scan_failed", {"reason": "cancelled"}),
    ]
    assert await claim_next(factory, INTERCEPTOR, "w") is None


async def test_cancel_flags_a_running_scan_for_its_workers(factory):
    # The interceptor job is running; the tracer job has not been claimed.
    scan_id = await _add_scan(factory, status="running", tracer={"status": "queued"})

    await _cancel(factory, scan_id)

    scan = await _scan(factory, scan_id)
    assert scan.status == "running" and scan.cancel_requested_at is not None
    assert (await _job(factory, scan_id, TRACER)).status == "cancelled"
    assert (await _job(factory, scan_id)).status == "running"
    assert await _event_types(factory, scan_id) == ["job_failed"]
    # The worker sees the request on its next heartbeat and ends its job.
    await _finish(factory, scan_id, INTERCEPTOR, JobStatus.cancelled, error="cancelled")
    assert (await _scan(factory, scan_id)).status == "cancelled"
    assert (await _events(factory, scan_id))[-1][1:] == ("scan_failed", {"reason": "cancelled"})


async def test_cancel_is_a_no_op_on_a_finished_scan(factory):
    scan_id = await _add_scan(factory, status="completed")
    await _cancel(factory, scan_id)
    scan = await _scan(factory, scan_id)
    assert scan.status == "completed" and scan.cancel_requested_at is None
    assert await _events(factory, scan_id) == []


class _FakeMapper:
    """Stands in for the crawler; map_website returns `result`, or blocks when it is None."""

    result = None
    started: asyncio.Event
    config = None

    def __init__(self, config, on_event=None):
        _FakeMapper.config = config
        self.on_event = on_event

    async def initialize(self):
        pass

    async def map_website(self):
        _FakeMapper.started.set()
        if _FakeMapper.result is None:
            await asyncio.sleep(3600)
        for service in _FakeMapper.result["external_services"]:
            await self.on_event("auth_detected", {"host": service["host"], "method": service["authentication"]})
        return _FakeMapper.result

    async def cleanup(self):
        pass


@pytest.fixture
def fake_mapper(monkeypatch):
    _FakeMapper.result = None
    _FakeMapper.started = asyncio.Event()
    _FakeMapper.config = None
    monkeypatch.setattr("worker.job.Mapper", _FakeMapper)
    return _FakeMapper


async def _start_job(factory, scan_id, make_config, settings=None) -> Job:
    row = await _job(factory, scan_id)
    job = Job(ClaimedJob(row.id, scan_id, INTERCEPTOR, "http://x", settings or {"max_depth": None}))
    job.task = asyncio.create_task(run_scan_job(job, make_config(), factory))
    return job


@pytest.mark.parametrize("reason, status, error, events", [
    (USER, "cancelled", "cancelled", [
        (0, "job_failed", {"scanner": "interceptor", "error": "cancelled"}),
        (1, "scan_failed", {"reason": "cancelled"}),
    ]),
    (SHUTDOWN, "failed", "worker shut down", [
        (0, "job_failed", {"scanner": "interceptor", "error": "worker shut down"}),
        (1, "scan_failed", {"error": "worker shut down"}),
    ]),
    (LEASE_LOST, "running", None, []),
])
async def test_cancelled_job_records_its_reason(factory, fake_mapper, make_config, reason, status, error, events):
    # A user's cancel reaches the worker as the scan's cancel request.
    requested = _now() if reason == USER else None
    scan_id = await _add_scan(factory, status="running", cancel_requested_at=requested)
    job = await _start_job(factory, scan_id, make_config)
    await fake_mapper.started.wait()

    job.request_cancel(reason)
    await asyncio.wait({job.task})

    assert job.task.cancelled()
    row = await _job(factory, scan_id)
    assert (row.status, row.error) == (status, error)
    scan = await _scan(factory, scan_id)
    assert (scan.status, scan.error) == (status, error)
    assert await _events(factory, scan_id) == events


async def test_completed_job_records_services_and_events(factory, fake_mapper, make_config):
    scan_id = await _add_scan(factory, status="running")
    fake_mapper.result = {
        "pages_crawled": 3,
        "external_services": [{
            "scheme": "https", "host": "a.example", "port": 443,
            "authentication": "ntlm", "ips": ["10.0.0.1"],
            "urls": [{"method": "GET", "url": "https://a.example/x", "status": 401,
                      "authentication": "ntlm", "page_url": "http://x"}],
            "evidence_index": 0,
        }],
    }
    job = await _start_job(factory, scan_id, make_config)
    await asyncio.wait({job.task})

    assert job.task.exception() is None
    assert (await _scan(factory, scan_id)).status == "completed"
    row = await _job(factory, scan_id)
    assert (row.status, row.pages_crawled) == ("completed", 3)
    [service] = await _services(factory, scan_id)
    assert (service.host, service.auth_method, service.severity) == ("a.example", "ntlm", "blocker")
    assert (service.request_count, service.ips) == (1, ["10.0.0.1"])
    assert await _findings(factory, service.id) == {"interceptor": ("ntlm", 1)}
    async with factory() as session:
        [url] = (await session.execute(select(UrlRow).where(UrlRow.service_id == service.id))).scalars().all()
    assert service.evidence_url_id == url.id
    assert (url.scanner, url.sources) == ("interceptor", [])
    events = await _events(factory, scan_id)
    assert [t for _, t, _ in events] == ["auth_detected", "job_completed", "blocker_found", "scan_completed"]
    assert events[0][2] == {"host": "a.example", "method": "ntlm", "scanner": "interceptor"}


async def test_job_settings_reach_the_crawler(factory, fake_mapper, make_config):
    scan_id = await _add_scan(factory, status="running")
    fake_mapper.result = {"pages_crawled": 0, "external_services": []}
    job = await _start_job(factory, scan_id, make_config, settings={"max_depth": 7})
    await asyncio.wait({job.task})
    assert (fake_mapper.config.start_url, fake_mapper.config.max_depth) == ("http://x", 7)


async def test_job_that_raises_records_failure(factory, fake_mapper, make_config, monkeypatch):
    scan_id = await _add_scan(factory, status="running")

    async def boom(self):
        raise RuntimeError("navigation exploded")

    monkeypatch.setattr(_FakeMapper, "map_website", boom)
    job = await _start_job(factory, scan_id, make_config)
    await asyncio.wait({job.task})

    assert job.task.exception() is None
    scan = await _scan(factory, scan_id)
    assert (scan.status, scan.error) == ("failed", "RuntimeError: navigation exploded")
    assert await _event_types(factory, scan_id) == ["job_failed", "scan_failed"]
