"""POST /scans, its cancel and GET /scans/{id} on the job queue, against a real
Postgres. Set TEST_DATABASE_URL to run."""
import uuid
from types import SimpleNamespace

from sqlalchemy import select

from api.models import CreateScanRequest
from api.routes_scans import cancel_scan, create_scan, get_scan
from core.db import AppRow, ScanEventRow, ScanJobRow, ScanRow
from core.enums import JobStatus, Scanner
from core.jobs import claim_next, finish


def _request(factory) -> SimpleNamespace:
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(session_factory=factory)))


async def _create_scan(factory, max_depth=None) -> str:
    """Request a scan of a new app, through the route."""
    app_id = uuid.uuid4().hex
    async with factory() as session:
        session.add(AppRow(id=app_id, name="app", url="http://x", owner_ad_group="g"))
        await session.commit()
    body = CreateScanRequest(app_id=app_id, max_depth=max_depth)
    return (await create_scan(body, _request(factory))).scan_id


async def _jobs(factory, scan_id) -> list:
    async with factory() as session:
        return (await session.execute(
            select(ScanJobRow).where(ScanJobRow.scan_id == scan_id)
        )).scalars().all()


async def _event_types(factory, scan_id) -> list:
    async with factory() as session:
        return (await session.execute(
            select(ScanEventRow.type).where(ScanEventRow.scan_id == scan_id).order_by(ScanEventRow.seq)
        )).scalars().all()


async def test_create_scan_enqueues_one_interceptor_job(factory):
    scan_id = await _create_scan(factory, max_depth=4)
    async with factory() as session:
        scan = await session.get(ScanRow, scan_id)
    assert scan.status == "queued"
    [job] = await _jobs(factory, scan_id)
    assert (job.scanner, job.status, job.settings, job.attempts) == ("interceptor", "queued", {"max_depth": 4}, 0)
    assert await _event_types(factory, scan_id) == ["scan_started"]
    # The committed job is the whole enqueue.
    claim = await claim_next(factory, Scanner.interceptor, "w")
    assert (claim.id, claim.url, claim.settings) == (job.id, "http://x", {"max_depth": 4})


async def test_create_scan_without_max_depth_leaves_it_to_the_worker(factory):
    scan_id = await _create_scan(factory)
    [job] = await _jobs(factory, scan_id)
    assert job.settings == {"max_depth": None}


async def test_cancel_scan_ends_a_queued_scan(factory):
    scan_id = await _create_scan(factory)
    response = await cancel_scan(scan_id, _request(factory))
    assert response.status_code == 204
    [job] = await _jobs(factory, scan_id)
    assert job.status == "cancelled"
    assert (await get_scan(scan_id, _request(factory))).status == "cancelled"
    assert await _event_types(factory, scan_id) == ["scan_started", "job_failed", "scan_failed"]


async def test_cancel_scan_leaves_a_running_scan_to_its_worker(factory):
    scan_id = await _create_scan(factory)
    await claim_next(factory, Scanner.interceptor, "w")
    await cancel_scan(scan_id, _request(factory))
    async with factory() as session:
        scan = await session.get(ScanRow, scan_id)
    assert scan.status == "running" and scan.cancel_requested_at is not None
    [job] = await _jobs(factory, scan_id)
    assert job.status == "running"


async def test_get_scan_reports_the_interceptor_jobs_pages(factory):
    scan_id = await _create_scan(factory)
    assert (await get_scan(scan_id, _request(factory))).pages_crawled == 0
    claim = await claim_next(factory, Scanner.interceptor, "w")
    async with factory() as session:
        await finish(session, claim.id, JobStatus.completed, pages_crawled=7)
        await session.commit()
    detail = await get_scan(scan_id, _request(factory))
    assert (detail.status, detail.pages_crawled) == ("completed", 7)
