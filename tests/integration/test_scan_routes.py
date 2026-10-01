"""POST /scans, its cancel and GET /scans/{id} on the job queue, against a real
Postgres. Set TEST_DATABASE_URL to run."""
import uuid
from types import SimpleNamespace

from sqlalchemy import select

from api.models import CreateScanRequest
from api.routes_scans import cancel_scan, create_scan, get_scan
from config_tracer.settings import ScanSettings
from core.db import AppRow, ScanEventRow, ScanJobRow, ScanRow
from core.enums import JobStatus, Scanner
from core.jobs import claim_next, finish


def _request(factory, tracer_settings=ScanSettings()) -> SimpleNamespace:
    state = SimpleNamespace(session_factory=factory, tracer_settings=tracer_settings)
    return SimpleNamespace(app=SimpleNamespace(state=state))


async def _create_scan(factory, max_depth=None, **state) -> str:
    """Request a scan of a new app, through the route."""
    app_id = uuid.uuid4().hex
    async with factory() as session:
        session.add(AppRow(id=app_id, name="app", url="http://x", owner_ad_group="g"))
        await session.commit()
    body = CreateScanRequest(app_id=app_id, max_depth=max_depth)
    return (await create_scan(body, _request(factory, **state))).scan_id


async def _jobs(factory, scan_id) -> dict:
    """The scan's jobs, by scanner."""
    async with factory() as session:
        rows = (await session.execute(
            select(ScanJobRow).where(ScanJobRow.scan_id == scan_id)
        )).scalars().all()
    return {Scanner(job.scanner): job for job in rows}


async def _event_types(factory, scan_id) -> list:
    async with factory() as session:
        return (await session.execute(
            select(ScanEventRow.type).where(ScanEventRow.scan_id == scan_id).order_by(ScanEventRow.seq)
        )).scalars().all()


async def test_create_scan_enqueues_a_job_per_scanner(factory):
    scan_id = await _create_scan(factory, max_depth=4)
    async with factory() as session:
        scan = await session.get(ScanRow, scan_id)
    assert scan.status == "queued"
    jobs = await _jobs(factory, scan_id)
    assert set(jobs) == set(Scanner)
    assert all((job.status, job.attempts) == ("queued", 0) for job in jobs.values())
    assert jobs[Scanner.interceptor].settings == {"max_depth": 4}
    assert jobs[Scanner.tracer].settings == ScanSettings().model_dump(mode="json")
    assert await _event_types(factory, scan_id) == ["scan_started"]
    # The committed jobs are the whole enqueue: a worker of each scanner claims its own.
    for scanner, job in jobs.items():
        claim = await claim_next(factory, scanner, "w")
        assert (claim.id, claim.url, claim.settings) == (job.id, "http://x", job.settings)


async def test_create_scan_without_max_depth_leaves_it_to_the_worker(factory):
    scan_id = await _create_scan(factory)
    assert (await _jobs(factory, scan_id))[Scanner.interceptor].settings == {"max_depth": None}


async def test_create_scan_snapshots_the_tracer_settings(factory):
    settings = ScanSettings(max_pages=7, follow_links=True, probe_timeout_s=2.5)
    scan_id = await _create_scan(factory, tracer_settings=settings)
    snapshot = (await _jobs(factory, scan_id))[Scanner.tracer].settings
    # Every field, so the scan no longer depends on anyone's environment.
    assert snapshot.keys() == ScanSettings.model_fields.keys()
    assert ScanSettings.model_validate(snapshot) == settings


async def test_cancel_scan_ends_a_queued_scan(factory):
    scan_id = await _create_scan(factory)
    response = await cancel_scan(scan_id, _request(factory))
    assert response.status_code == 204
    assert [job.status for job in (await _jobs(factory, scan_id)).values()] == ["cancelled", "cancelled"]
    assert (await get_scan(scan_id, _request(factory))).status == "cancelled"
    assert await _event_types(factory, scan_id) == ["scan_started", "job_failed", "job_failed", "scan_failed"]


async def test_cancel_scan_leaves_a_running_job_to_its_worker(factory):
    scan_id = await _create_scan(factory)
    await claim_next(factory, Scanner.interceptor, "w")
    await cancel_scan(scan_id, _request(factory))
    async with factory() as session:
        scan = await session.get(ScanRow, scan_id)
    assert scan.status == "running" and scan.cancel_requested_at is not None
    jobs = await _jobs(factory, scan_id)
    # The tracer job was still queued, so it ends at once.
    assert (jobs[Scanner.interceptor].status, jobs[Scanner.tracer].status) == ("running", "cancelled")


async def test_get_scan_reports_the_interceptor_jobs_pages(factory):
    scan_id = await _create_scan(factory)
    assert (await get_scan(scan_id, _request(factory))).pages_crawled == 0
    # The tracer counts no pages.
    for scanner, pages_crawled, status in (
        (Scanner.interceptor, 7, "running"),
        (Scanner.tracer, None, "completed"),
    ):
        claim = await claim_next(factory, scanner, "w")
        async with factory() as session:
            await finish(session, claim.id, JobStatus.completed, pages_crawled=pages_crawled)
            await session.commit()
        detail = await get_scan(scan_id, _request(factory))
        assert (detail.status, detail.pages_crawled) == (status, 7)
