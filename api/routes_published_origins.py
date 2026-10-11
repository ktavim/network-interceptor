"""The published-origins registry: origins already published through the F5.

One registry for every app. A service on a registered origin is published,
whatever its auth method, on every scan whose verdicts are computed while the
entry is active (core.jobs._recompute_services). A scan completed before a
change keeps its verdicts, so the change shows on the next scan.
"""
import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from core.db import PublishedOriginRow

from .models import CreatePublishedOriginRequest, PublishedOrigin
from .routes_me import _STUB_USER
from .serialize import published_origin_to_schema

router = APIRouter()

_ALREADY_REGISTERED = "origin already registered as published"


def _session_factory(request: Request) -> async_sessionmaker[AsyncSession]:
    return request.app.state.session_factory


@router.get("/published-origins", response_model=List[PublishedOrigin])
async def list_published_origins(
    request: Request, include_removed: bool = False
) -> List[PublishedOrigin]:
    """The active entries, in origin order; with `include_removed`, the
    removed ones as well, an origin's in the order they were added."""
    factory = _session_factory(request)
    async with factory() as session:
        stmt = select(PublishedOriginRow).order_by(
            PublishedOriginRow.host,
            PublishedOriginRow.port,
            PublishedOriginRow.scheme,
            PublishedOriginRow.added_at,
        )
        if not include_removed:
            stmt = stmt.where(PublishedOriginRow.removed_at.is_(None))
        rows = (await session.execute(stmt)).scalars().all()
    return [published_origin_to_schema(row) for row in rows]


@router.post("/published-origins", response_model=PublishedOrigin, status_code=201)
async def create_published_origin(
    body: CreatePublishedOriginRequest, request: Request
) -> PublishedOrigin:
    factory = _session_factory(request)
    async with factory() as session:
        active = (
            await session.execute(
                select(PublishedOriginRow.id).where(
                    PublishedOriginRow.scheme == body.scheme,
                    PublishedOriginRow.host == body.host,
                    PublishedOriginRow.port == body.port,
                    PublishedOriginRow.removed_at.is_(None),
                )
            )
        ).scalar_one_or_none()
        if active is not None:
            raise HTTPException(status_code=409, detail={"message": _ALREADY_REGISTERED})
        row = PublishedOriginRow(
            id="pub_" + uuid.uuid4().hex[:10],
            scheme=body.scheme,
            host=body.host,
            port=body.port,
            note=body.note,
            added_by=_STUB_USER.username,
        )
        session.add(row)
        try:
            await session.commit()
        except IntegrityError:
            # Lost a race: another registration of the origin committed first
            # and the partial unique index on active entries rejected ours.
            await session.rollback()
            raise HTTPException(status_code=409, detail={"message": _ALREADY_REGISTERED})
        await session.refresh(row)
    return published_origin_to_schema(row)


@router.delete("/published-origins/{origin_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_published_origin(origin_id: str, request: Request) -> Response:
    """Remove a registration. A soft delete: a scan completed while it was
    active keeps its verdicts and its services keep pointing at the entry."""
    factory = _session_factory(request)
    async with factory() as session:
        row = await session.get(PublishedOriginRow, origin_id)
        if row is None:
            raise HTTPException(status_code=404, detail={"message": "published origin not found"})
        if row.removed_at is not None:
            raise HTTPException(status_code=404, detail={"message": "published origin already removed"})
        row.removed_at = datetime.now(timezone.utc)
        row.removed_by = _STUB_USER.username
        await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
