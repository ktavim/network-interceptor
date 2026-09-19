"""SSE event bus: per-subscriber queues, durable replay via scan_events."""
import asyncio
import logging
import time
from typing import Any, Dict, Optional, Set

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .db import ScanEventRow

logger = logging.getLogger(__name__)


class EventBus:
    """A registry of per-scan subscribers. Producers fan out to live queues
    while persisting every event for durable resume."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._subscribers: Dict[str, Set[asyncio.Queue]] = {}
        self._notification_subscribers: Set[asyncio.Queue] = set()
        self._session_factory = session_factory
        self._lock = asyncio.Lock()

    def subscribers_for(self, scan_id: str) -> Set[asyncio.Queue]:
        return self._subscribers.setdefault(scan_id, set())

    async def subscribe(self, scan_id: str, queue: asyncio.Queue) -> None:
        async with self._lock:
            self.subscribers_for(scan_id).add(queue)

    async def unsubscribe(self, scan_id: str, queue: asyncio.Queue) -> None:
        async with self._lock:
            subs = self._subscribers.get(scan_id)
            if subs and queue in subs:
                subs.discard(queue)
                if not subs:
                    self._subscribers.pop(scan_id, None)

    async def subscribe_notifications(self, queue: asyncio.Queue) -> None:
        async with self._lock:
            self._notification_subscribers.add(queue)

    async def unsubscribe_notifications(self, queue: asyncio.Queue) -> None:
        async with self._lock:
            self._notification_subscribers.discard(queue)

    async def next_seq(self, scan_id: str) -> int:
        async with self._session_factory() as session:
            stmt = select(func.coalesce(func.max(ScanEventRow.seq), -1)).where(
                ScanEventRow.scan_id == scan_id
            )
            result = await session.execute(stmt)
            current = result.scalar_one()
            return int(current) + 1

    async def emit(
        self,
        scan_id: str,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        seq: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Persist + fan out an event. Returns the event dict.

        Fan-out is best-effort: full subscriber queues drop and log."""
        if seq is None:
            seq = await self.next_seq(scan_id)
        ts = int(time.time() * 1000)
        payload = payload or {}

        async with self._session_factory() as session:
            session.add(
                ScanEventRow(
                    scan_id=scan_id,
                    seq=seq,
                    ts=ts,
                    type=event_type,
                    payload=payload,
                )
            )
            await session.commit()

        event = {
            "scan_id": scan_id,
            "seq": str(seq),
            "ts": ts,
            "type": event_type,
            "payload": payload,
        }

        for queue in list(self._subscribers.get(scan_id, set())):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning("SSE subscriber queue full for scan %s; dropping event", scan_id)

        if event_type in ("scan_completed", "scan_failed"):
            for queue in list(self._notification_subscribers):
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    logger.warning("Notification queue full; dropping event for scan %s", scan_id)
        return event


async def replay_events(
    session_factory: async_sessionmaker[AsyncSession],
    scan_id: str,
    start_seq: int,
):
    async with session_factory() as session:
        stmt = (
            select(ScanEventRow)
            .where(ScanEventRow.scan_id == scan_id, ScanEventRow.seq >= start_seq)
            .order_by(ScanEventRow.seq.asc())
        )
        result = await session.execute(stmt)
        return [row for row in result.scalars()]
