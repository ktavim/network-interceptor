"""One claimed job: run its scanner on the scan's target, then record the outcome."""
import asyncio
import copy
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from config_loader import Config
from config_tracer.pipeline import run_scan
from config_tracer.settings import ScanSettings
from core.enums import JobStatus
from core.events import emit_event_now
from core.jobs import CANCELLED, ClaimedJob, finish, requeue
from core.translate import services_to_rows, tracer_report_to_rows
from crawler import Mapper

logger = logging.getLogger(__name__)

# Why a job was cancelled; decides what it records.
USER = "user"
SHUTDOWN = "shutdown"
LEASE_LOST = "lease_lost"

# What a scanner's run comes to: its service rows and url rows, in the shape
# core.translate returns, and the pages it crawled (None if it counts none).
Results = Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Optional[int]]


@dataclass
class Job:
    claim: ClaimedJob
    task: Optional[asyncio.Task] = None
    reason: Optional[str] = None
    finalizing: bool = False

    def request_cancel(self, reason: str) -> None:
        # Once only: a second cancel would interrupt the cleanup or the terminal write.
        if self.reason is None and not self.finalizing and self.task is not None:
            self.reason = reason
            self.task.cancel()


def build_request_config(base: Config, *, start_url: str, max_depth: int | None) -> Config:
    cfg = copy.deepcopy(base)
    cfg.start_url = start_url
    if max_depth is not None:
        cfg.max_depth = max_depth
    return cfg


@asynccontextmanager
async def scan_timeout(seconds: float) -> AsyncIterator[None]:
    """The hard cap on one run of a scanner's engine, SCAN_TIMEOUT_S.

    Past it the engine is cancelled where it stands, so its own cleanup runs,
    and the TimeoutError raised names the cap. A TimeoutError the engine
    raises by itself passes through unchanged, as does a cancel of the job.
    """
    deadline = asyncio.timeout(seconds)
    try:
        async with deadline:
            yield
    except TimeoutError as e:
        if not deadline.expired():
            raise
        raise TimeoutError(f"scan exceeded SCAN_TIMEOUT_S={seconds:g}s") from e


async def record_failure(
    session_factory: async_sessionmaker[AsyncSession], job_id: str, status: JobStatus, error: str
) -> None:
    """End the job as failed or cancelled, unless it has already ended."""
    async with session_factory() as session:
        await finish(session, job_id, status, error=error)
        await session.commit()


async def _record_interrupted(
    session_factory: async_sessionmaker[AsyncSession], job_id: str, reason: str
) -> None:
    if reason == USER:
        await record_failure(session_factory, job_id, JobStatus.cancelled, CANCELLED)
    elif reason == SHUTDOWN:
        # Not the job's failure: the next worker of its scanner runs it again.
        await requeue(session_factory, job_id)
    # LEASE_LOST: the reaper already ended the job.


async def _record_completed(
    session_factory: async_sessionmaker[AsyncSession],
    claim: ClaimedJob,
    results: Results,
) -> None:
    service_rows, url_rows, pages_crawled = results
    async with session_factory() as session:
        # A reaped job records no services.
        if not await finish(
            session,
            claim.id,
            JobStatus.completed,
            pages_crawled=pages_crawled,
            service_rows=service_rows,
            url_rows=url_rows,
        ):
            logger.warning("Job %s of scan %s ended while finishing; dropping its results", claim.id, claim.scan_id)
            return
        await session.commit()


async def _run_job(
    job: Job,
    session_factory: async_sessionmaker[AsyncSession],
    scan: Callable[[], Awaitable[Results]],
) -> None:
    """Run `scan`, a scanner's engine on the scan of job.claim, and record how the job ended.

    Raises only the CancelledError it was sent.
    """
    claim = job.claim
    try:
        results = await scan()
        job.finalizing = True
        await _record_completed(session_factory, claim, results)
    except asyncio.CancelledError:
        await _record_interrupted(session_factory, claim.id, job.reason or SHUTDOWN)
        raise
    except Exception as e:
        # A cancel can surface as a browser error instead, e.g. Target closed.
        if job.reason is not None:
            await _record_interrupted(session_factory, claim.id, job.reason)
            return
        logger.exception("Scan %s failed (%s)", claim.scan_id, claim.url)
        await record_failure(session_factory, claim.id, JobStatus.failed, f"{e.__class__.__name__}: {e}")


async def run_interceptor_job(
    job: Job,
    session_factory: async_sessionmaker[AsyncSession],
    base_config: Config,
    timeout_s: float,
) -> None:
    """Crawl the scan of job.claim and record how the job ended. Raises only the CancelledError it was sent."""
    claim = job.claim

    async def on_event(event_type: str, payload: Dict[str, Any]) -> None:
        if event_type == "auth_detected":
            # Each scanner announces its own verdict for an origin.
            payload = {**payload, "scanner": claim.scanner.value}
        await emit_event_now(session_factory, claim.scan_id, event_type, payload)

    async def crawl() -> Results:
        config = build_request_config(
            base_config, start_url=claim.url, max_depth=claim.settings.get("max_depth")
        )
        mapper = Mapper(config, on_event=on_event)
        try:
            async with scan_timeout(timeout_s):
                await mapper.initialize()
                result = await mapper.map_website()
        finally:
            await mapper.cleanup()
        service_rows, url_rows = services_to_rows(claim.scan_id, result.get("external_services", []))
        return service_rows, url_rows, int(result.get("pages_crawled", 0) or 0)

    await _run_job(job, session_factory, crawl)


async def run_tracer_job(
    job: Job,
    session_factory: async_sessionmaker[AsyncSession],
    timeout_s: float,
) -> None:
    """Trace the scan of job.claim and record how the job ended. Raises only the CancelledError it was sent."""
    claim = job.claim

    async def trace() -> Results:
        # The snapshot taken when the scan was requested, not this process's environment.
        settings = ScanSettings.model_validate(claim.settings)
        async with scan_timeout(timeout_s):
            report = await run_scan([claim.url], settings)
        service_rows, url_rows = tracer_report_to_rows(claim.scan_id, report)
        # The pipeline reports nothing while it runs, so each origin's verdict
        # is announced once it returns.
        for row in service_rows:
            payload = {
                "scheme": row["scheme"],
                "host": row["host"],
                "port": row["port"],
                "method": row["auth_method"],
                "scanner": claim.scanner.value,
            }
            try:
                await emit_event_now(session_factory, claim.scan_id, "auth_detected", payload)
            except Exception as e:
                # As for the crawler's events: a lost announcement does not fail the scan.
                logger.warning("Could not emit auth_detected for scan %s: %s", claim.scan_id, e)
        return service_rows, url_rows, None

    await _run_job(job, session_factory, trace)
