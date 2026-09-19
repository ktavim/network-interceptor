import asyncio
import json
import logging

from fastapi import APIRouter, HTTPException, Request
from sse_starlette.sse import EventSourceResponse

from .db import ScanRow
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

    queue: asyncio.Queue = asyncio.Queue(maxsize=1024)
    if not terminal:
        await bus.subscribe(scan_id, queue)

    async def event_gen():
        try:
            replay = await replay_events(factory, scan_id, start_seq)
            max_seq = start_seq - 1
            for row in replay:
                event_obj = {
                    "scan_id": row.scan_id,
                    "seq": str(row.seq),
                    "ts": row.ts,
                    "type": row.type,
                    "payload": row.payload,
                }
                yield _format(row.seq, event_obj)
                if row.seq > max_seq:
                    max_seq = row.seq

            if terminal:
                return

            while True:
                if await request.is_disconnected():
                    return
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    yield {"comment": "keepalive"}
                    continue
                seq_int = int(event["seq"])
                if seq_int <= max_seq:
                    continue
                max_seq = seq_int
                yield _format(event["seq"], event)
                if event["type"] in ("scan_completed", "scan_failed"):
                    return
        finally:
            if not terminal:
                await bus.unsubscribe(scan_id, queue)

    return EventSourceResponse(event_gen())


@router.get("/notifications")
async def notifications(request: Request):
    bus = request.app.state.event_bus
    queue: asyncio.Queue = asyncio.Queue(maxsize=1024)
    await bus.subscribe_notifications(queue)

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
            await bus.unsubscribe_notifications(queue)

    return EventSourceResponse(gen())
