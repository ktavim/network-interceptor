"""SSE event bus: Postgres NOTIFY wakes per-scan streams and feeds the notifications stream."""
import asyncio
import logging
from typing import Dict, Set

import asyncpg
from sqlalchemy import select
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from core.db import ScanEventRow, _database_url
from core.events import CHANNEL, TERMINAL_EVENTS, event_to_dict, parse_notification

logger = logging.getLogger(__name__)

PING_INTERVAL = 30.0
MAX_RECONNECT_DELAY = 30.0


def _asyncpg_dsn() -> str:
    url = make_url(_database_url()).set(drivername="postgresql")
    return url.render_as_string(hide_password=False)


class EventBus:
    """Scan streams read events from the DB; a notification only wakes them."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory
        self._wakers: Dict[str, Set[asyncio.Event]] = {}
        self._notification_subscribers: Set[asyncio.Queue] = set()
        self._terminal: asyncio.Queue = asyncio.Queue()

    def subscribe(self, scan_id: str, wake: asyncio.Event) -> None:
        self._wakers.setdefault(scan_id, set()).add(wake)

    def unsubscribe(self, scan_id: str, wake: asyncio.Event) -> None:
        wakers = self._wakers.get(scan_id)
        if wakers is not None:
            wakers.discard(wake)
            if not wakers:
                del self._wakers[scan_id]

    def subscribe_notifications(self, queue: asyncio.Queue) -> None:
        self._notification_subscribers.add(queue)

    def unsubscribe_notifications(self, queue: asyncio.Queue) -> None:
        self._notification_subscribers.discard(queue)

    def _wake_all(self) -> None:
        for wakers in self._wakers.values():
            for wake in wakers:
                wake.set()

    # A plain def: asyncpg runs sync callbacks in arrival order.
    def _on_notify(self, _conn, _pid, _channel, payload: str) -> None:
        try:
            scan_id, seq, event_type = parse_notification(payload)
        except ValueError:
            logger.warning("Ignoring malformed %s notification: %r", CHANNEL, payload)
            return
        for wake in self._wakers.get(scan_id, ()):
            wake.set()
        if event_type in TERMINAL_EVENTS and self._notification_subscribers:
            self._terminal.put_nowait((scan_id, seq))

    async def _dispatch_notifications(self) -> None:
        while True:
            scan_id, seq = await self._terminal.get()
            try:
                async with self._session_factory() as session:
                    row = await session.get(ScanEventRow, (scan_id, seq))
            except Exception as e:
                logger.warning("Could not read event %s/%d for notifications: %s", scan_id, seq, e)
                continue
            if row is None:
                continue
            event = event_to_dict(row)
            for queue in list(self._notification_subscribers):
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    logger.warning("Notification queue full; dropping event for scan %s", scan_id)

    async def run(self) -> None:
        """LISTEN until cancelled, reconnecting whenever the connection fails."""
        dispatcher = asyncio.create_task(self._dispatch_notifications())
        delay = 1.0
        try:
            while True:
                conn = None
                try:
                    conn = await asyncpg.connect(_asyncpg_dsn())
                    await conn.add_listener(CHANNEL, self._on_notify)
                    delay = 1.0
                    # Whatever was emitted while disconnected woke no one.
                    self._wake_all()
                    while True:
                        await asyncio.sleep(PING_INTERVAL)
                        # An idle LISTEN connection that dies silently raises nothing by itself.
                        await conn.fetchval("SELECT 1", timeout=5)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.warning("Event listener failed (%s); reconnecting in %.0fs", e, delay)
                finally:
                    if conn is not None:
                        conn.terminate()
                await asyncio.sleep(delay)
                delay = min(delay * 2, MAX_RECONNECT_DELAY)
        finally:
            dispatcher.cancel()


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
