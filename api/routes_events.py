import asyncio
import json
import logging

from fastapi import APIRouter, HTTPException, Request
from sse_starlette.sse import EventSourceResponse

from core.db import ScanRow
from core.events import TERMINAL_EVENTS, event_to_dict

from .sse import replay_events

logger = logging.getLogger(__name__)

router = APIRouter()


def _format(seq: int | str, data: dict) -> dict:
    return {"id": str(seq), "data": json.dumps(data)}


@router.get("/scans/{scan_id}/events")
async def scan_events(scan_id: str, request: Request):
    app_state = request.app.state
    factory = app_state.session_factory
    bus = app_state.event_bus

    async with factory() as session:
        scan = await session.get(ScanRow, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail={"message": "scan not found"})

    last_event_id = request.headers.get("Last-Event-ID")
    try:
        start_seq = int(last_event_id) + 1 if last_event_id else 0
    except (TypeError, ValueError):
        start_seq = 0

    terminal = scan.status in ("completed", "failed", "cancelled")

    # Subscribed before the first read, so no wake-up is missed in between.
    wake = asyncio.Event()
    if not terminal:
        bus.subscribe(scan_id, wake)

    async def event_gen():
        next_seq = start_seq
        try:
            while True:
                wake.clear()
                for row in await replay_events(factory, scan_id, next_seq):
                    yield _format(row.seq, event_to_dict(row))
                    next_seq = row.seq + 1
                    if row.type in TERMINAL_EVENTS:
                        return
                if terminal or await request.is_disconnected():
                    return
                try:
                    await asyncio.wait_for(wake.wait(), timeout=15.0)
                except asyncio.TimeoutError:
                    yield {"comment": "keepalive"}
        finally:
            if not terminal:
                bus.unsubscribe(scan_id, wake)

    return EventSourceResponse(event_gen())


@router.get("/notifications")
async def notifications(request: Request):
    bus = request.app.state.event_bus
    queue: asyncio.Queue = asyncio.Queue(maxsize=1024)
    bus.subscribe_notifications(queue)

    async def gen():
        try:
            while True:
                if await request.is_disconnected():
                    return
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=25.0)
                except asyncio.TimeoutError:
                    yield {"comment": "keepalive"}
                    continue
                yield _format(event["seq"], event)
        finally:
            bus.unsubscribe_notifications(queue)

    return EventSourceResponse(gen())
