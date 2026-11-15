"""The exposure console's API: the queue, the history and one exposure's
workspace (docs/exposure-design.md, Admin API).

Read-only so far. Every endpoint here will require the `admin` role; like the
rest of the API it is unauthenticated until real identity replaces the /me
stub, and must not reach production before then.
"""
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from core import exposures
from core.db import AppRow, ExposureRow, SubmissionRow, load_services
from core.enums import CLOSED_EXPOSURE_STATUSES, ExposureScope, ExposureStatus

from .models import (
    ExposureApp,
    ExposureDetail,
    ExposureGroup,
    ExposureNotice,
    ExposureService,
    ExposureSummary,
)
from .serialize import _isoformat, published_origin_to_schema, service_to_schema

router = APIRouter()


def _session_factory(request: Request) -> async_sessionmaker[AsyncSession]:
    return request.app.state.session_factory


def _notice(notice: exposures.Notice) -> ExposureNotice:
    return ExposureNotice(code=notice.code, message=notice.message, service_id=notice.service_id)


def _summary(
    exposure: ExposureRow,
    app: AppRow,
    submitted_at: datetime,
    submitted_by: str,
    assessment: exposures.Assessment,
) -> dict:
    return dict(
        id=exposure.id,
        status=exposure.status,
        version=exposure.version,
        app=ExposureApp(id=app.id, name=app.name, url=app.url),
        scan_id=exposure.scan_id,
        submitted_at=_isoformat(submitted_at),
        submitted_by=submitted_by,
        created_at=_isoformat(exposure.created_at),
        needs_vip_count=assessment.needs_vip_count,
        blocked=bool(assessment.blocked_by),
    )


def _with_submission():
    return (
        select(ExposureRow, AppRow, SubmissionRow.submitted_at, SubmissionRow.submitted_by)
        .join(AppRow, AppRow.id == ExposureRow.app_id)
        .join(SubmissionRow, SubmissionRow.scan_id == ExposureRow.scan_id)
    )


@router.get("/exposures", response_model=List[ExposureSummary])
async def list_exposures(
    request: Request, status: Optional[List[ExposureStatus]] = Query(default=None)
) -> List[ExposureSummary]:
    """The queue: the open exposures, oldest submission first. With one or
    more `status`, the exposures in those instead, newest submission first,
    as the history lists them."""
    stmt = _with_submission()
    if status:
        stmt = stmt.where(ExposureRow.status.in_([s.value for s in status]))
        stmt = stmt.order_by(SubmissionRow.submitted_at.desc())
    else:
        stmt = stmt.where(ExposureRow.status.not_in([s.value for s in CLOSED_EXPOSURE_STATUSES]))
        stmt = stmt.order_by(SubmissionRow.submitted_at.asc())

    async with _session_factory(request)() as session:
        rows = (await session.execute(stmt)).all()
        scan_ids = [exposure.scan_id for exposure, *_ in rows]
        services = await exposures.load_scan_services(session, scan_ids)
        members = await exposures.load_group_members(session, [e.id for e, *_ in rows])
        registry = await exposures.load_registry(session)

    out = []
    for exposure, app, submitted_at, submitted_by in rows:
        # The queue shows no warnings, so the scanners that found each
        # service are not needed.
        assessment = exposures.assess(
            app_url=app.url,
            services=services[exposure.scan_id],
            found_by={},
            group_of=members[exposure.id],
            registry=registry,
        )
        out.append(ExposureSummary(**_summary(exposure, app, submitted_at, submitted_by, assessment)))
    return out


@router.get("/exposures/{exposure_id}", response_model=ExposureDetail)
async def get_exposure(exposure_id: str, request: Request) -> ExposureDetail:
    async with _session_factory(request)() as session:
        row = (
            await session.execute(_with_submission().where(ExposureRow.id == exposure_id))
        ).first()
        if row is None:
            raise HTTPException(status_code=404, detail={"message": "exposure not found"})
        exposure, app, submitted_at, submitted_by = row
        loaded = await load_services(session, exposure.scan_id)
        groups = await exposures.load_groups(session, exposure.id)
        group_of = (await exposures.load_group_members(session, [exposure.id]))[exposure.id]
        registry = await exposures.load_registry(session)
        supersedes = (
            await session.execute(
                select(ExposureRow.id).where(ExposureRow.superseded_by_id == exposure.id)
            )
        ).scalar_one_or_none()

    assessment = exposures.assess(
        app_url=app.url,
        services=[service for service, *_ in loaded],
        found_by={
            service.id: [finding.scanner for finding, _ in findings]
            for service, _, findings, _, _ in loaded
        },
        group_of=group_of,
        registry=registry,
        scan_entries={
            service.id: entry for service, _, _, _, entry in loaded if entry is not None
        },
    )

    services: List[ExposureService] = []
    for loaded_service in loaded:
        service = loaded_service[0]
        scope = assessment.services[service.id]
        services.append(ExposureService(
            **service_to_schema(*loaded_service).model_dump(),
            scope=scope.scope,
            # Only a service that needs a VIP is grouped. One that was grouped
            # and has been published since leaves its group on the next save.
            group_id=(
                group_of.get(service.id) if scope.scope is ExposureScope.needs_vip else None
            ),
            registry_entry=(
                published_origin_to_schema(scope.registry_entry)
                if scope.registry_entry is not None
                else None
            ),
            warnings=[_notice(w) for w in scope.warnings],
        ))
    return ExposureDetail(
        **_summary(exposure, app, submitted_at, submitted_by, assessment),
        groups=[
            ExposureGroup(
                id=group.id,
                service_ids=[s.id for s in services if s.group_id == group.id],
            )
            for group in groups
        ],
        services=services,
        blocked_by=[_notice(n) for n in assessment.blocked_by],
        supersedes=supersedes,
        superseded_by=exposure.superseded_by_id,
    )
