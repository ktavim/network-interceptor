"""The scans table as the job queue. Every timestamp here is the database's now()."""
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence

from sqlalchemy import case, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from core.db import ScanRow
from core.events import emit_event

LEASE_TIMEOUT = timedelta(seconds=60)
WORKER_LOST = "worker lost"


@dataclass
class ClaimedScan:
    id: str
    url: str
    max_depth: Optional[int]


def _update_scans():
    return update(ScanRow).execution_options(synchronize_session=False)


async def claim_next(
    session_factory: async_sessionmaker[AsyncSession], worker_id: str
) -> Optional[ClaimedScan]:
    """Claim the oldest queued scan, or None if there is none."""
    # NO KEY UPDATE: plain FOR UPDATE conflicts with each event insert's FOR KEY SHARE, and SKIP LOCKED would pass the scan over.
    oldest = (
        select(ScanRow.id)
        .where(ScanRow.status == "queued")
        .order_by(ScanRow.started_at)
        .limit(1)
        .with_for_update(skip_locked=True, key_share=True)
        .scalar_subquery()
    )
    stmt = (
        _update_scans()
        .where(ScanRow.id == oldest)
        .values(status="running", started_at=func.now(), worker_id=worker_id, heartbeat_at=func.now())
        .returning(ScanRow.id, ScanRow.url, ScanRow.max_depth)
    )
    async with session_factory() as session:
        row = (await session.execute(stmt)).first()
        await session.commit()
    return ClaimedScan(*row) if row else None


async def release(session_factory: async_sessionmaker[AsyncSession], scan_id: str) -> None:
    """Put a claimed scan that never started back in the queue."""
    async with session_factory() as session:
        await session.execute(
            _update_scans()
            .where(ScanRow.id == scan_id, ScanRow.status == "running")
            .values(status="queued", worker_id=None, heartbeat_at=None)
        )
        await session.commit()


async def heartbeat(
    session_factory: async_sessionmaker[AsyncSession], scan_ids: Sequence[str]
) -> Dict[str, Optional[datetime]]:
    """Refresh the lease on these scans: {scan_id: cancel_requested_at} for each still running."""
    if not scan_ids:
        return {}
    stmt = (
        _update_scans()
        .where(ScanRow.id.in_(scan_ids), ScanRow.status == "running")
        .values(heartbeat_at=func.now())
        .returning(ScanRow.id, ScanRow.cancel_requested_at)
    )
    async with session_factory() as session:
        rows = (await session.execute(stmt)).all()
        await session.commit()
    return {scan_id: cancel_requested_at for scan_id, cancel_requested_at in rows}


async def reap_stale(
    session_factory: async_sessionmaker[AsyncSession], own_ids: Sequence[str]
) -> List[str]:
    """End running scans whose worker stopped heartbeating; returns their ids."""
    cancel_requested = ScanRow.cancel_requested_at.is_not(None)
    stmt = (
        _update_scans()
        .where(
            ScanRow.status == "running",
            ScanRow.heartbeat_at < func.now() - LEASE_TIMEOUT,
            ScanRow.id.not_in(own_ids),
        )
        .values(
            status=case((cancel_requested, "cancelled"), else_="failed"),
            error=case((cancel_requested, "cancelled"), else_=WORKER_LOST),
            completed_at=func.now(),
        )
        .returning(ScanRow.id, ScanRow.status)
    )
    async with session_factory() as session:
        rows = (await session.execute(stmt)).all()
        for scan_id, status in rows:
            payload = {"reason": "cancelled"} if status == "cancelled" else {"error": WORKER_LOST}
            await emit_event(session, scan_id, "scan_failed", payload)
        await session.commit()
    return [scan_id for scan_id, _ in rows]


async def finish(session: AsyncSession, scan_id: str, status: str, **values: Any) -> bool:
    """End a running scan in the caller's transaction; False if it had already ended."""
    result = await session.execute(
        _update_scans()
        .where(ScanRow.id == scan_id, ScanRow.status == "running")
        .values(status=status, completed_at=func.now(), **values)
    )
    return result.rowcount == 1
