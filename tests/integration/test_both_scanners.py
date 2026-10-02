"""A scan with a worker of each scanner: both runners of worker.job with their
engines stubbed, from POST /scans through the queue into a real Postgres, read
back through the API's routes. Set TEST_DATABASE_URL to run.
"""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import select, update

from api.models import CreateAppRequest, CreateScanRequest, PatchServiceRequest
from api.routes_apps import create_app, list_apps
from api.routes_events import scan_events
from api.routes_scans import (
    cancel_scan,
    create_scan,
    get_scan,
    list_service_urls,
    list_services,
    patch_service,
    submit_scan,
)
from api.sse import EventBus
from config_tracer.models import AuthMethod as TracerAuthMethod
from config_tracer.models import HttpMethod, Origin
from config_tracer.report import ScanReport, ServiceReport, UrlEvidence
from config_tracer.settings import ScanSettings
from core.db import ScanEventRow, ScanJobRow
from core.enums import Scanner
from core.jobs import claim_next, heartbeat, reap_stale
from worker.job import SHUTDOWN, USER, Job, run_interceptor_job, run_tracer_job

# A scan timeout no test job reaches.
NO_TIMEOUT = 3600
APP_URL = "http://x"


def _request(factory, **headers) -> SimpleNamespace:
    async def is_disconnected():
        return False

    state = SimpleNamespace(
        session_factory=factory, tracer_settings=ScanSettings(), event_bus=EventBus(factory)
    )
    return SimpleNamespace(app=SimpleNamespace(state=state), headers=headers, is_disconnected=is_disconnected)


async def _request_scan(factory) -> str:
    """Create an app and request a scan of it, through the routes. Returns the scan id."""
    app = await create_app(CreateAppRequest(name="app", url=APP_URL, owner_ad_group="g"), _request(factory))
    return (await create_scan(CreateScanRequest(app_id=app.id), _request(factory))).scan_id


@pytest.fixture
def start_job(factory, make_config):
    """Do what a worker of a scanner does with the queue's next job: claim it and start its runner."""
    async def start(scanner: Scanner) -> Job:
        job = Job(await claim_next(factory, scanner, f"{scanner.value}-worker"))
        if scanner is Scanner.tracer:
            run = run_tracer_job(job, factory, NO_TIMEOUT)
        else:
            run = run_interceptor_job(job, factory, make_config(), NO_TIMEOUT)
        job.task = asyncio.create_task(run)
        return job

    return start


async def _beat(factory, jobs) -> None:
    """One beat of a worker's heartbeat loop: it stops a job whose scan has a cancel requested."""
    held = await heartbeat(factory, [job.claim.id for job in jobs])
    for job in jobs:
        if held[job.claim.id] is not None:
            job.request_cancel(USER)


async def _events(factory, scan_id) -> list:
    """The scan's events in order, as (type, payload)."""
    async with factory() as session:
        rows = await session.execute(
            select(ScanEventRow).where(ScanEventRow.scan_id == scan_id).order_by(ScanEventRow.seq)
        )
        return [(row.type, row.payload) for row in rows.scalars()]


async def _stream(factory, scan_id, **headers) -> list:
    """The types of the events GET /scans/{id}/events sends before it closes the stream."""
    response = await scan_events(scan_id, _request(factory, **headers))
    # A stream left open would send keepalives for ever.
    async with asyncio.timeout(5):
        return [json.loads(event["data"])["type"] async for event in response.body_iterator]


async def _services(factory, scan_id) -> dict:
    """The scan's services as GET /scans/{id}/services lists them, by host."""
    return {s.host: s for s in await list_services(scan_id, _request(factory))}


def _observed(host, tag, paths, ips, **request) -> dict:
    """One origin as the crawler reports it: the requests the browser made to it."""
    return {
        "scheme": "https", "host": host, "port": 443, "authentication": tag, "ips": ips,
        "urls": [
            {"method": "GET", "url": f"https://{host}{path}", "status": 200, "authentication": tag,
             "resource_type": "xhr", "page_url": f"{APP_URL}/", **request}
            for path in paths
        ],
        "evidence_index": 0,
    }


def _probed(host, verdict, url, ips, challenge=None) -> ServiceReport:
    """One origin as the tracer reports it: a URL the app's bundle names, and the probe's 401."""
    evidence = UrlEvidence(
        url=url, http_method=HttpMethod.HEAD, status_code=401, www_authenticate=challenge,
        detected_method=verdict, sources=[f"js: {APP_URL}/main.js?v=3"],
    )
    return ServiceReport(origin=Origin("https", host, 443), ips=ips, auth_verdict=verdict, urls_probed=1, urls=[evidence])


def _crawl() -> dict:
    """What the stubbed crawler finds: a token API the browser calls, and a CDN."""
    return {
        "pages_crawled": 4,
        "external_services": [
            _observed("api.example", "bearer", ["/v1/items", "/v1/me"], ["10.0.0.1"], sent_auth_scheme="Bearer"),
            _observed("cdn.example", "unauthenticated", ["/app.css"], ["10.0.0.9"]),
        ],
    }


def _trace() -> ScanReport:
    """What the stubbed tracer finds: the same API, whose base answers an anonymous
    probe with a bare 401, and a Basic-auth host that no page calls."""
    return ScanReport(suspect_urls=[], services=[
        _probed("api.example", TracerAuthMethod.UNKNOWN, "https://api.example/v1?key=sk-123", ["10.0.0.1", "10.0.0.2"]),
        _probed("legacy.example", TracerAuthMethod.BASIC, "https://legacy.example/reports", ["10.0.0.7"],
                challenge='Basic realm="reports"'),
    ])


async def test_both_scanners_findings_come_back_as_one_list_of_services(factory, fake_mapper, fake_pipeline, start_job):
    fake_mapper.result, fake_pipeline.report = _crawl(), _trace()
    scan_id = await _request_scan(factory)

    jobs = [await start_job(scanner) for scanner in Scanner]
    # Both end at once, each merging its findings into the scan under the scan's lock.
    await asyncio.gather(*(job.task for job in jobs))

    request = _request(factory)
    detail = await get_scan(scan_id, request)
    assert (detail.status, detail.service_count, detail.blocker_count) == ("completed", 3, 1)
    assert [(j.scanner, j.status, j.error, j.pages_crawled) for j in detail.jobs] == [
        ("interceptor", "completed", None, 4),
        # The tracer counts no pages; the scan's are the interceptor's.
        ("tracer", "completed", None, None),
    ]
    assert all(j.started_at and j.completed_at for j in detail.jobs)
    assert detail.pages_crawled == 4

    services = await _services(factory, scan_id)
    assert {host: (s.auth_method, s.severity, s.found_by) for host, s in services.items()} == {
        # The token-API case: the bearer token the browser used beats the probe's bare 401.
        "api.example": ("bearer", "cleared", ["interceptor", "tracer"]),
        "cdn.example": ("unauthenticated", "cleared", ["interceptor"]),
        "legacy.example": ("basic", "blocker", ["tracer"]),
    }
    api = services["api.example"]
    # Each scanner's own verdict is kept, with the request it rests on.
    observed, probed = api.findings
    assert (observed.scanner, observed.auth_method, observed.severity) == ("interceptor", "bearer", "cleared")
    assert (probed.scanner, probed.auth_method, probed.severity) == ("tracer", "unknown", "review")
    assert (observed.evidence.url, observed.evidence.sent_auth_scheme) == ("https://api.example/v1/items", "Bearer")
    assert (probed.evidence.url, probed.evidence.status_code) == ("https://api.example/v1", 401)
    # The service's evidence is the winning finding's, and its counts cover both scanners.
    assert api.evidence == observed.evidence
    assert (api.request_count, api.ips) == (3, ["10.0.0.1", "10.0.0.2"])
    [finding] = services["legacy.example"].findings
    assert services["legacy.example"].evidence == finding.evidence
    assert finding.evidence.auth_challenge == 'Basic realm="reports"'

    urls = await list_service_urls(scan_id, api.id, request)
    assert [(u.scanner, u.url, u.resource_type, u.page_url, u.sources) for u in urls] == [
        ("tracer", "https://api.example/v1", "probe", "", [f"js: {APP_URL}/main.js"]),
        ("interceptor", "https://api.example/v1/items", "xhr", f"{APP_URL}/", []),
        ("interceptor", "https://api.example/v1/me", "xhr", f"{APP_URL}/", []),
    ]
    assert await list_service_urls(scan_id, api.id, request, scanner=Scanner.tracer) == urls[:1]
    assert await list_service_urls(scan_id, api.id, request, scanner=Scanner.interceptor) == urls[1:]

    events = await _events(factory, scan_id)
    # Each scanner announces its own verdict for the origin they share.
    assert {(p["scanner"], p["method"]) for t, p in events if t == "auth_detected" and p["host"] == "api.example"} == {
        ("interceptor", "bearer"), ("tracer", "unknown"),
    }
    # Blockers are announced once the scan ends, from the combined verdicts.
    assert [p["host"] for t, p in events if t == "blocker_found"] == ["legacy.example"]
    last_type, last = events[-1]
    assert last.pop("duration_ms") >= 0
    assert (last_type, last) == (
        "scan_completed", {"services": 3, "blockers": 1, "partial": False, "failed_scanners": []},
    )


async def test_scan_with_a_failed_scanner_ends_partial_and_can_only_be_rerun(factory, fake_mapper, start_job, monkeypatch):
    async def crash(seeds, settings):
        raise RuntimeError("browser closed")

    monkeypatch.setattr("worker.job.run_scan", crash)
    fake_mapper.result = _crawl()
    scan_id = await _request_scan(factory)

    jobs = [await start_job(scanner) for scanner in Scanner]
    await asyncio.gather(*(job.task for job in jobs))

    request = _request(factory)
    detail = await get_scan(scan_id, request)
    assert (detail.status, detail.completed_at is not None) == ("partial", True)
    assert [(j.scanner, j.status, j.error) for j in detail.jobs] == [
        ("interceptor", "completed", None),
        ("tracer", "failed", "RuntimeError: browser closed"),
    ]
    # The scanner that completed keeps its services.
    services = await _services(factory, scan_id)
    assert {host: s.found_by for host, s in services.items()} == {
        "api.example": ["interceptor"], "cdn.example": ["interceptor"],
    }

    events = await _events(factory, scan_id)
    last_type, last = events[-1]
    assert (last_type, last["partial"], last["failed_scanners"]) == ("scan_completed", True, ["tracer"])
    # The scan's stream ends there, and a client resuming past the end is not left waiting.
    stream = await _stream(factory, scan_id)
    assert stream == [t for t, _ in events]
    assert await _stream(factory, scan_id, **{"Last-Event-ID": str(len(events) - 1)}) == []

    # A scanner's results are missing, so the scan can be neither submitted nor edited.
    with pytest.raises(HTTPException) as refused:
        await submit_scan(scan_id, request)
    assert (refused.value.status_code, refused.value.detail) == (
        409, {"message": "scan is partial, only completed scans can be submitted"},
    )
    with pytest.raises(HTTPException) as refused:
        await patch_service(scan_id, services["cdn.example"].id, PatchServiceRequest(excluded=True), request)
    assert (refused.value.status_code, refused.value.detail) == (
        409, {"message": "only the latest completed scan can be edited"},
    )
    # What is left is a rerun: the app reads as failed, and says why.
    [app] = await list_apps(request)
    assert (app.exposure_state, app.last_scan_id, app.last_scan_status) == ("failed", scan_id, "partial")


async def test_cancel_mid_run_ends_both_jobs_and_the_scan_once(factory, fake_mapper, fake_pipeline, start_job):
    # Neither stub has a result, so both engines run until they are stopped.
    scan_id = await _request_scan(factory)
    jobs = [await start_job(scanner) for scanner in Scanner]
    await asyncio.gather(fake_mapper.started.wait(), fake_pipeline.started.wait())

    request = _request(factory)
    assert (await cancel_scan(scan_id, request)).status_code == 204
    # Only a request until each worker's next heartbeat sees it.
    assert (await get_scan(scan_id, request)).status == "running"
    await _beat(factory, jobs)
    await asyncio.wait({job.task for job in jobs})

    assert all(job.task.cancelled() for job in jobs)
    detail = await get_scan(scan_id, request)
    assert (detail.status, detail.service_count) == ("cancelled", 0)
    assert [(j.scanner, j.status, j.error) for j in detail.jobs] == [
        ("interceptor", "cancelled", "cancelled"),
        ("tracer", "cancelled", "cancelled"),
    ]
    # Whichever job ends second ends the scan: one terminal event, after both jobs'.
    events = await _events(factory, scan_id)
    assert [t for t, _ in events] == [
        "scan_started", "job_started", "job_started", "job_failed", "job_failed", "scan_failed",
    ]
    assert events[-1][1] == {"reason": "cancelled"}
    with pytest.raises(HTTPException) as refused:
        await submit_scan(scan_id, request)
    assert refused.value.status_code == 409


async def test_job_requeued_by_a_worker_shutdown_is_run_again_and_the_scan_completes(factory, fake_mapper, fake_pipeline, start_job):
    fake_pipeline.report = _trace()
    scan_id = await _request_scan(factory)
    await (await start_job(Scanner.tracer)).task
    # The interceptor's worker shuts down mid-crawl.
    stopped = await start_job(Scanner.interceptor)
    await fake_mapper.started.wait()
    stopped.request_cancel(SHUTDOWN)
    await asyncio.wait({stopped.task})

    # Its job waits for a worker again; the scan and the tracer's services stand.
    request = _request(factory)
    detail = await get_scan(scan_id, request)
    assert detail.status == "running"
    assert [(j.scanner, j.status, j.error) for j in detail.jobs] == [
        ("interceptor", "queued", None),
        ("tracer", "completed", None),
    ]
    assert detail.jobs[0].started_at is None
    assert set(await _services(factory, scan_id)) == {"api.example", "legacy.example"}

    # The next interceptor worker runs the job from the start, and the scan ends as if nothing had happened.
    fake_mapper.result = _crawl()
    await (await start_job(Scanner.interceptor)).task

    detail = await get_scan(scan_id, request)
    assert (detail.status, detail.service_count, detail.blocker_count) == ("completed", 3, 1)
    assert [(j.scanner, j.status, j.error, j.pages_crawled) for j in detail.jobs] == [
        ("interceptor", "completed", None, 4),
        ("tracer", "completed", None, None),
    ]
    assert [t for t, _ in await _events(factory, scan_id)] == [
        "scan_started",
        "job_started", "auth_detected", "auth_detected", "job_completed",
        "job_started", "job_requeued",
        "job_started", "auth_detected", "auth_detected", "job_completed",
        "blocker_found", "scan_completed",
    ]


async def test_reaped_job_ends_its_scan_with_the_other_scanners_results(factory, fake_pipeline, start_job):
    fake_pipeline.report = _trace()
    scan_id = await _request_scan(factory)
    # An interceptor worker claims its job and dies: the job's lease goes stale.
    lost = await claim_next(factory, Scanner.interceptor, "dead-worker")
    async with factory() as session:
        await session.execute(
            update(ScanJobRow)
            .where(ScanJobRow.id == lost.id)
            .values(heartbeat_at=datetime.now(timezone.utc) - timedelta(minutes=5))
        )
        await session.commit()
    await (await start_job(Scanner.tracer)).task

    # The tracer's services show, each with the tracer's verdict alone, while the
    # scan waits on a job that nobody is running.
    request = _request(factory)
    assert (await get_scan(scan_id, request)).status == "running"
    traced = {
        "api.example": ("unknown", "review", ["tracer"]),
        "legacy.example": ("basic", "blocker", ["tracer"]),
    }
    services = await _services(factory, scan_id)
    assert {host: (s.auth_method, s.severity, s.found_by) for host, s in services.items()} == traced

    # Any worker's reaper ends the lost job, and with it the scan.
    assert await reap_stale(factory, []) == [lost.id]

    detail = await get_scan(scan_id, request)
    assert (detail.status, detail.blocker_count) == ("partial", 1)
    assert [(j.scanner, j.status, j.error) for j in detail.jobs] == [
        ("interceptor", "failed", "worker lost"),
        ("tracer", "completed", None),
    ]
    services = await _services(factory, scan_id)
    assert {host: (s.auth_method, s.severity, s.found_by) for host, s in services.items()} == traced
    # Finalized like a scan whose last job ended by itself: blockers, then the terminal event.
    events = await _events(factory, scan_id)
    assert [t for t, _ in events[-3:]] == ["job_failed", "blocker_found", "scan_completed"]
    assert events[-3][1] == {"scanner": "interceptor", "error": "worker lost"}
    assert events[-2][1]["host"] == "legacy.example"
    assert (events[-1][1]["partial"], events[-1][1]["failed_scanners"]) == (True, ["interceptor"])
