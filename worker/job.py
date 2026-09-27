"""One claimed scan: crawl it, then record the outcome."""
import asyncio
import copy
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from config_loader import Config
from core.db import ServiceRow, UrlRow
from core.enums import Severity
from core.events import emit_event, emit_event_now
from core.translate import services_to_rows
from crawler import Mapper

from .queue import ClaimedScan, finish

logger = logging.getLogger(__name__)

# Why a job was cancelled; decides what it records.
USER = "user"
SHUTDOWN = "shutdown"
LEASE_LOST = "lease_lost"

WORKER_SHUT_DOWN = "worker shut down"


@dataclass
class Job:
    scan: ClaimedScan
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
    session_factory: async_sessionmaker[AsyncSession], scan_id: str, status: str, error: str
) -> None:
    """End the scan with a scan_failed event, unless it has already ended."""
    payload: Dict[str, Any] = {"reason": "cancelled"} if status == "cancelled" else {"error": error}
    async with session_factory() as session:
        if await finish(session, scan_id, status, error=error):
            await emit_event(session, scan_id, "scan_failed", payload)
        await session.commit()


async def _record_interrupted(
    session_factory: async_sessionmaker[AsyncSession], scan_id: str, reason: str
) -> None:
    if reason == USER:
        await record_failure(session_factory, scan_id, "cancelled", "cancelled")
    elif reason == SHUTDOWN:
        await record_failure(session_factory, scan_id, "failed", WORKER_SHUT_DOWN)
    # LEASE_LOST: the reaper already ended the scan.


async def _record_completed(
    session_factory: async_sessionmaker[AsyncSession],
    scan_id: str,
    result: Dict[str, Any],
    started_ms: int,
) -> None:
    pages_crawled = int(result.get("pages_crawled", 0) or 0)
    service_rows, url_rows = services_to_rows(scan_id, result.get("external_services", []))
    blockers = [r for r in service_rows if r["severity"] == Severity.blocker.value]
    async with session_factory() as session:
        # The scan row first, for lock order; a reaped scan gets no services.
        if not await finish(session, scan_id, "completed", pages_crawled=pages_crawled):
            logger.warning("Scan %s ended while finishing; dropping its results", scan_id)
            return
        # Services before urls; services.evidence_url_id is deferred, so it may point ahead.
        session.add_all([ServiceRow(**r) for r in service_rows])
        session.add_all([UrlRow(**r) for r in url_rows])
        for r in blockers:
            await emit_event(session, scan_id, "blocker_found", {
                "scheme": r["scheme"],
                "host": r["host"],
                "port": r["port"],
                "auth_method": r["auth_method"],
            })
        await emit_event(session, scan_id, "scan_completed", {
            "duration_ms": int(time.time() * 1000) - started_ms,
            "services": len(service_rows),
            "blockers": len(blockers),
        })
        await session.commit()


async def run_scan_job(
    job: Job,
    base_config: Config,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Crawl job.scan and record how it ended. Raises only the CancelledError it was sent."""
    scan = job.scan
    started_ms = int(time.time() * 1000)

    async def on_event(event_type: str, payload: Dict[str, Any]) -> None:
        await emit_event_now(session_factory, scan.id, event_type, payload)

    try:
        config = build_request_config(base_config, start_url=scan.url, max_depth=scan.max_depth)
        mapper = Mapper(config, on_event=on_event)
        try:
            await mapper.initialize()
            result = await mapper.map_website()
        finally:
            await mapper.cleanup()
        job.finalizing = True
        await _record_completed(session_factory, scan.id, result, started_ms)
    except asyncio.CancelledError:
        await _record_interrupted(session_factory, scan.id, job.reason or SHUTDOWN)
        raise
    except Exception as e:
        # A cancel can surface as a browser error instead, e.g. Target closed.
        if job.reason is not None:
            await _record_interrupted(session_factory, scan.id, job.reason)
            return
        logger.exception("Scan %s failed (%s)", scan.id, scan.url)
        await record_failure(session_factory, scan.id, "failed", f"{e.__class__.__name__}: {e}")
