"""The scan_jobs table as the job queue, and the scans its jobs belong to.

A scan is one request and its work is one job per scanner. Workers claim,
lease and end jobs here. Whatever ends a job also runs finalize_scan, which
keeps the scan's services and status in step with its jobs.

Every transaction takes its locks in one order: job rows, then the scan row,
then events (core.events). Every timestamp here is the database's now().
"""
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence

from sqlalchemy import Row, case, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .db import ScanJobRow, ScanRow, ServiceFindingRow, ServiceRow, UrlRow
from .enums import AuthMethod, JobStatus, Scanner, ScanStatus, Severity
from .events import emit_event
from .merge import Finding, merge_findings

LEASE_TIMEOUT = timedelta(seconds=60)
WORKER_LOST = "worker lost"
# The error of a job or scan that ended because a cancel was requested.
CANCELLED = "cancelled"

_QUEUED = JobStatus.queued.value
_RUNNING = JobStatus.running.value
# The scan statuses that are not final: its jobs can still change it.
_OPEN = (ScanStatus.queued.value, ScanStatus.running.value)


@dataclass
class ClaimedJob:
    id: str
    scan_id: str
    scanner: Scanner
    url: str
    settings: Dict[str, Any]


def scan_status(job_statuses: Sequence[JobStatus], cancel_requested: bool) -> ScanStatus:
    """A scan's status, from its jobs'."""
    if all(s is JobStatus.queued for s in job_statuses):
        return ScanStatus.queued
    if any(s in (JobStatus.queued, JobStatus.running) for s in job_statuses):
        return ScanStatus.running
    # Every job has finished. A job is only ever cancelled by a cancel request.
    if cancel_requested or JobStatus.cancelled in job_statuses:
        return ScanStatus.cancelled
    if all(s is JobStatus.completed for s in job_statuses):
        return ScanStatus.completed
    if any(s is JobStatus.completed for s in job_statuses):
        return ScanStatus.partial
    return ScanStatus.failed


def _update_jobs():
    return update(ScanJobRow).execution_options(synchronize_session=False)


def _update_scans():
    return update(ScanRow).execution_options(synchronize_session=False)


async def _lock_scan(session: AsyncSession, scan_id: str) -> Row:
    """Lock the scan row until commit; returns its status, url, started_at and cancel_requested_at."""
    # NO KEY UPDATE: plain FOR UPDATE would block on the FOR KEY SHARE that each event insert
    # takes on the scan through scan_events' foreign key.
    return (
        await session.execute(
            select(ScanRow.status, ScanRow.url, ScanRow.started_at, ScanRow.cancel_requested_at)
            .where(ScanRow.id == scan_id)
            .with_for_update(key_share=True)
        )
    ).one()


async def claim_next(
    session_factory: async_sessionmaker[AsyncSession], scanner: Scanner, worker_id: str
) -> Optional[ClaimedJob]:
    """Claim the oldest queued job for this scanner, or None if there is none."""
    oldest = (
        select(ScanJobRow.id)
        .where(ScanJobRow.scanner == scanner.value, ScanJobRow.status == _QUEUED)
        .order_by(ScanJobRow.created_at)
        .limit(1)
        .with_for_update(skip_locked=True, key_share=True)
        .scalar_subquery()
    )
    stmt = (
        _update_jobs()
        .where(ScanJobRow.id == oldest)
        .values(
            status=_RUNNING,
            started_at=func.now(),
            worker_id=worker_id,
            heartbeat_at=func.now(),
            attempts=ScanJobRow.attempts + 1,
        )
        .returning(ScanJobRow.id, ScanJobRow.scan_id, ScanJobRow.settings)
    )
    async with session_factory() as session:
        row = (await session.execute(stmt)).first()
        if row is None:
            return None
        job_id, scan_id, settings = row
        scan = await _lock_scan(session, scan_id)
        # The scan starts with the first of its jobs to be claimed.
        if scan.status == ScanStatus.queued.value:
            await session.execute(
                _update_scans()
                .where(ScanRow.id == scan_id)
                .values(status=ScanStatus.running.value, started_at=func.now())
            )
        await emit_event(session, scan_id, "job_started", {"scanner": scanner.value})
        await session.commit()
    return ClaimedJob(job_id, scan_id, scanner, scan.url, settings)


async def release(session_factory: async_sessionmaker[AsyncSession], job_id: str) -> None:
    """Put a claimed job that never started back in the queue."""
    async with session_factory() as session:
        scan_id = (
            await session.execute(
                _update_jobs()
                .where(ScanJobRow.id == job_id, ScanJobRow.status == _RUNNING)
                .values(status=_QUEUED, started_at=None, worker_id=None, heartbeat_at=None)
                .returning(ScanJobRow.scan_id)
            )
        ).scalar_one_or_none()
        if scan_id is not None:
            await _lock_scan(session, scan_id)
            # The scan goes back too, unless another of its jobs has started.
            started = (
                select(ScanJobRow.id)
                .where(ScanJobRow.scan_id == scan_id, ScanJobRow.status != _QUEUED)
                .exists()
            )
            await session.execute(
                _update_scans()
                .where(ScanRow.id == scan_id, ScanRow.status == ScanStatus.running.value, ~started)
                .values(status=ScanStatus.queued.value)
            )
        await session.commit()


async def heartbeat(
    session_factory: async_sessionmaker[AsyncSession], job_ids: Sequence[str]
) -> Dict[str, Optional[datetime]]:
    """Refresh the lease on these jobs: {job_id: its scan's cancel_requested_at} for each still running."""
    if not job_ids:
        return {}
    stmt = (
        _update_jobs()
        .where(
            ScanJobRow.id.in_(job_ids),
            ScanJobRow.status == _RUNNING,
            ScanRow.id == ScanJobRow.scan_id,
        )
        .values(heartbeat_at=func.now())
        .returning(ScanJobRow.id, ScanRow.cancel_requested_at)
    )
    async with session_factory() as session:
        rows = (await session.execute(stmt)).all()
        await session.commit()
    return {job_id: cancel_requested_at for job_id, cancel_requested_at in rows}


async def reap_stale(
    session_factory: async_sessionmaker[AsyncSession], own_ids: Sequence[str]
) -> List[str]:
    """End running jobs whose worker stopped heartbeating, whatever their scanner; returns their ids."""
    cancel_requested = ScanRow.cancel_requested_at.is_not(None)
    stmt = (
        _update_jobs()
        .where(
            ScanJobRow.status == _RUNNING,
            ScanJobRow.heartbeat_at < func.now() - LEASE_TIMEOUT,
            ScanJobRow.id.not_in(own_ids),
            ScanRow.id == ScanJobRow.scan_id,
        )
        .values(
            status=case((cancel_requested, JobStatus.cancelled.value), else_=JobStatus.failed.value),
            error=case((cancel_requested, CANCELLED), else_=WORKER_LOST),
            completed_at=func.now(),
        )
        .returning(ScanJobRow.id, ScanJobRow.scan_id, ScanJobRow.scanner, ScanJobRow.error)
    )
    async with session_factory() as session:
        rows = (await session.execute(stmt)).all()
        by_scan: Dict[str, List[Row]] = {}
        for row in rows:
            by_scan.setdefault(row.scan_id, []).append(row)
        # In id order, so two reapers take the scan locks the same way round.
        for scan_id in sorted(by_scan):
            await _lock_scan(session, scan_id)
            for row in by_scan[scan_id]:
                await emit_event(
                    session, scan_id, "job_failed", {"scanner": row.scanner, "error": row.error}
                )
            await finalize_scan(session, scan_id)
        await session.commit()
    return [row.id for row in rows]


async def finish(
    session: AsyncSession,
    job_id: str,
    status: JobStatus,
    *,
    error: Optional[str] = None,
    pages_crawled: Optional[int] = None,
    service_rows: Sequence[Dict[str, Any]] = (),
    url_rows: Sequence[Dict[str, Any]] = (),
) -> bool:
    """End a running job in the caller's transaction, then finalize its scan.

    False if the job had already ended; nothing is written then.
    `service_rows` and `url_rows` are a completed job's results, the services
    as its scanner alone sees them, in the shape core.translate returns.
    """
    ended = (
        await session.execute(
            _update_jobs()
            .where(ScanJobRow.id == job_id, ScanJobRow.status == _RUNNING)
            .values(
                status=status.value,
                completed_at=func.now(),
                error=error,
                pages_crawled=pages_crawled,
            )
            .returning(ScanJobRow.scan_id, ScanJobRow.scanner)
        )
    ).first()
    if ended is None:
        return False
    scan_id, scanner = ended
    # Held from here on: everything that writes a scan's services does so under its lock.
    await _lock_scan(session, scan_id)
    await _record_findings(session, scan_id, scanner, service_rows, url_rows)
    if status is JobStatus.completed:
        payload = {"scanner": scanner, "services": len(service_rows)}
        await emit_event(session, scan_id, "job_completed", payload)
    else:
        await emit_event(session, scan_id, "job_failed", {"scanner": scanner, "error": error})
    await finalize_scan(session, scan_id)
    return True


async def cancel(session: AsyncSession, scan_id: str) -> None:
    """Cancel a scan in the caller's transaction; a no-op once the scan has ended.

    Its queued jobs end here. A running job ends when its worker next
    heartbeats and sees the request.
    """
    # Conditional updates: a worker claiming a job concurrently can't slip between them.
    dequeued = (
        await session.execute(
            _update_jobs()
            .where(ScanJobRow.scan_id == scan_id, ScanJobRow.status == _QUEUED)
            .values(status=JobStatus.cancelled.value, completed_at=func.now(), error=CANCELLED)
            .returning(ScanJobRow.scanner)
        )
    ).scalars().all()
    requested = await session.execute(
        _update_scans()
        .where(ScanRow.id == scan_id, ScanRow.status.in_(_OPEN))
        .values(cancel_requested_at=func.now())
    )
    if not requested.rowcount:
        return
    for scanner in dequeued:
        await emit_event(session, scan_id, "job_failed", {"scanner": scanner, "error": CANCELLED})
    await finalize_scan(session, scan_id)


async def finalize_scan(session: AsyncSession, scan_id: str) -> None:
    """Bring a scan up to date with its jobs, in the transaction that ended one of them.

    Recomputes each service's combined verdict, so one scanner's results show
    while another still runs. Once every job has finished, sets the scan's
    final status and emits blocker_found per combined blocker, then the
    terminal event.

    A no-op on a scan that has its final status: nothing here can overwrite a
    manual auth fix, which is only possible on a completed scan.
    """
    scan = await _lock_scan(session, scan_id)
    if scan.status not in _OPEN:
        return
    services = await _recompute_services(session, scan_id)
    jobs = (
        await session.execute(
            select(ScanJobRow.scanner, ScanJobRow.status, ScanJobRow.error)
            .where(ScanJobRow.scan_id == scan_id)
            .order_by(ScanJobRow.scanner)
        )
    ).all()
    status = scan_status(
        [JobStatus(job.status) for job in jobs], scan.cancel_requested_at is not None
    )
    if status.value in _OPEN:
        return

    failed = [job for job in jobs if job.status == JobStatus.failed.value]
    if status is ScanStatus.cancelled:
        error = CANCELLED
    elif len(jobs) == 1:
        error = jobs[0].error
    else:
        # More than one scanner ran, so say whose error each is.
        error = "; ".join(f"{job.scanner}: {job.error}" for job in failed) or None
    completed_at = (
        await session.execute(
            _update_scans()
            .where(ScanRow.id == scan_id)
            .values(status=status.value, completed_at=func.now(), error=error)
            .returning(ScanRow.completed_at)
        )
    ).scalar_one()

    if status is ScanStatus.cancelled:
        await emit_event(session, scan_id, "scan_failed", {"reason": CANCELLED})
    elif status is ScanStatus.failed:
        await emit_event(session, scan_id, "scan_failed", {"error": error})
    else:
        blockers = [s for s in services if s.severity == Severity.blocker.value]
        for service in blockers:
            await emit_event(session, scan_id, "blocker_found", {
                "scheme": service.scheme,
                "host": service.host,
                "port": service.port,
                "auth_method": service.auth_method,
            })
        await emit_event(session, scan_id, "scan_completed", {
            "duration_ms": int((completed_at - scan.started_at).total_seconds() * 1000),
            "services": len(services),
            "blockers": len(blockers),
            "partial": status is ScanStatus.partial,
            "failed_scanners": [job.scanner for job in failed],
        })


async def _record_findings(
    session: AsyncSession,
    scan_id: str,
    scanner: str,
    service_rows: Sequence[Dict[str, Any]],
    url_rows: Sequence[Dict[str, Any]],
) -> None:
    """Add one scanner's services and urls to the scan.

    Each service row becomes this scanner's finding for the origin. An origin
    another scanner already reported keeps its service row and gains the
    finding, the urls and any new addresses. The caller holds the scan row's
    lock, so no one else is writing the scan's services.
    """
    if not service_rows:
        return
    stored = {
        (s.scheme, s.host, s.port): s
        for s in (
            await session.execute(select(ServiceRow).where(ServiceRow.scan_id == scan_id))
        ).scalars()
    }
    # The id each service row was translated with -> the id of the row that holds the origin.
    service_ids: Dict[str, str] = {}
    for row in service_rows:
        service = stored.get((row["scheme"], row["host"], row["port"]))
        if service is None:
            # Its verdict is this scanner's until _recompute_services combines the findings.
            session.add(ServiceRow(**row))
            service_ids[row["id"]] = row["id"]
        else:
            ips = list(dict.fromkeys((service.ips or []) + (row["ips"] or [])))
            service.ips = ips or None
            service_ids[row["id"]] = service.id
        session.add(ServiceFindingRow(
            service_id=service_ids[row["id"]],
            scanner=scanner,
            auth_method=row["auth_method"],
            evidence_url_id=row["evidence_url_id"],
            url_count=row["request_count"],
        ))
    # Services before urls; the evidence keys are deferred, so they may point ahead.
    session.add_all(
        UrlRow(**{**row, "service_id": service_ids[row["service_id"]]}) for row in url_rows
    )


async def _recompute_services(session: AsyncSession, scan_id: str) -> List[ServiceRow]:
    """Set each of the scan's services to the combined verdict of its findings; returns the services."""
    rows = (
        await session.execute(
            select(ServiceRow, ServiceFindingRow)
            .join(ServiceFindingRow, ServiceFindingRow.service_id == ServiceRow.id)
            .where(ServiceRow.scan_id == scan_id)
            .order_by(ServiceRow.host, ServiceRow.port, ServiceRow.scheme)
        )
    ).all()
    findings: Dict[ServiceRow, List[ServiceFindingRow]] = {}
    for service, finding in rows:
        findings.setdefault(service, []).append(finding)
    for service, own in findings.items():
        # No scanner's addresses are kept apart; the service's are the union. That is exact
        # where the merge reads has_ips, to drop a tracer dns_failed: the tracer resolved
        # none, so any address is the interceptor's.
        verdict = merge_findings(
            Finding(
                scanner=Scanner(f.scanner),
                auth_method=AuthMethod(f.auth_method),
                evidence_url_id=f.evidence_url_id,
                has_ips=bool(service.ips),
            )
            for f in own
        )
        service.auth_method = verdict.auth_method.value
        service.severity = verdict.severity.value
        service.evidence_url_id = verdict.evidence_url_id
        service.request_count = sum(f.url_count for f in own)
    return list(findings)
