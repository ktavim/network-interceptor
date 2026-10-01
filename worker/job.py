"""One claimed job: crawl its scan's target, then record the outcome."""
import asyncio
import copy
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from config_loader import Config
from core.enums import JobStatus
from core.events import emit_event_now
from core.jobs import CANCELLED, ClaimedJob, finish
from core.translate import services_to_rows
from crawler import Mapper

logger = logging.getLogger(__name__)

# Why a job was cancelled; decides what it records.
USER = "user"
SHUTDOWN = "shutdown"
LEASE_LOST = "lease_lost"

WORKER_SHUT_DOWN = "worker shut down"


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
        await record_failure(session_factory, job_id, JobStatus.failed, WORKER_SHUT_DOWN)
    # LEASE_LOST: the reaper already ended the job.


async def _record_completed(
    session_factory: async_sessionmaker[AsyncSession],
    claim: ClaimedJob,
    result: Dict[str, Any],
) -> None:
    pages_crawled = int(result.get("pages_crawled", 0) or 0)
    service_rows, url_rows = services_to_rows(claim.scan_id, result.get("external_services", []))
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


async def run_scan_job(
    job: Job,
    base_config: Config,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Crawl the scan of job.claim and record how the job ended. Raises only the CancelledError it was sent."""
    claim = job.claim

    async def on_event(event_type: str, payload: Dict[str, Any]) -> None:
        if event_type == "auth_detected":
            # Each scanner announces its own verdict for an origin.
            payload = {**payload, "scanner": claim.scanner.value}
        await emit_event_now(session_factory, claim.scan_id, event_type, payload)

    try:
        config = build_request_config(
            base_config, start_url=claim.url, max_depth=claim.settings.get("max_depth")
        )
        mapper = Mapper(config, on_event=on_event)
        try:
            await mapper.initialize()
            result = await mapper.map_website()
        finally:
            await mapper.cleanup()
        job.finalizing = True
        await _record_completed(session_factory, claim, result)
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
