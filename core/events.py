"""Scan events: durable rows in scan_events, announced with NOTIFY on commit."""
import time
from typing import Any, Dict, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .db import ScanEventRow

CHANNEL = "scan_events"
TERMINAL_EVENTS = ("scan_completed", "scan_failed")


def event_to_dict(row: ScanEventRow) -> Dict[str, Any]:
    return {
        "scan_id": row.scan_id,
        "seq": str(row.seq),
        "ts": row.ts,
        "type": row.type,
        "payload": row.payload,
    }


def parse_notification(payload: str) -> Tuple[str, int, str]:
    """(scan_id, seq, type) from a NOTIFY payload; ValueError if malformed."""
    scan_id, seq, event_type = payload.split(":", 2)
    return scan_id, int(seq), event_type


async def emit_event(
    session: AsyncSession,
    scan_id: str,
    event_type: str,
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Add an event to the caller's transaction; update the scans row first, never after (lock order)."""
    # Held to commit; max() as its own statement then sees every seq committed before it.
    await session.execute(select(func.pg_advisory_xact_lock(func.hashtext(scan_id))))
    current = (
        await session.execute(
            select(func.coalesce(func.max(ScanEventRow.seq), -1)).where(
                ScanEventRow.scan_id == scan_id
            )
        )
    ).scalar_one()
    row = ScanEventRow(
        scan_id=scan_id,
        seq=int(current) + 1,
        ts=int(time.time() * 1000),
        type=event_type,
        payload=payload or {},
    )
    session.add(row)
    await session.flush()
    # Ids only: a payload can exceed NOTIFY's 8000-byte limit.
    await session.execute(
        select(func.pg_notify(CHANNEL, f"{scan_id}:{row.seq}:{event_type}"))
    )
    return event_to_dict(row)


async def emit_event_now(
    session_factory: async_sessionmaker[AsyncSession],
    scan_id: str,
    event_type: str,
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    async with session_factory() as session:
        event = await emit_event(session, scan_id, event_type, payload)
        await session.commit()
    return event
