"""The exposure console's API: the queue, the history and one exposure's
workspace (docs/exposure-design.md, Admin API).

Read-only so far. Every endpoint here will require the `admin` role; like the
rest of the API it is unauthenticated until real identity replaces the /me
stub, and must not reach production before then.
"""
import asyncio
import json
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from sse_starlette.sse import EventSourceResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from core import exposure_lifecycle, exposures
from core.db import AppRow, ExposureRow, SubmissionRow, load_services
from core.enums import CLOSED_EXPOSURE_STATUSES, ExposureScope, ExposureStatus

from .models import (
    ConfirmRequest,
    ExposureApp,
    ExposureDetail,
    ExposureFailure,
    ExposureGroup,
    ExposureNotice,
    ExposureService,
    ExposureSummary,
    SaveGroupingRequest,
    VersionRequest,
)
from .routes_me import _STUB_USER
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
        deploying = await exposures.load_deploying(session, list({e.app_id for e, *_ in rows}))

    out = []
    for exposure, app, submitted_at, submitted_by in rows:
        # The queue shows no warnings, so the scanners that found each
        # service are not needed.
        assessment = exposures.assess(
            services=services[exposure.scan_id],
            found_by={},
            group_of=members[exposure.id],
            registry=exposures.registry_for(registry, exposure.id),
            deploying=[d for d in deploying[exposure.app_id] if d != exposure.id],
        )
        out.append(ExposureSummary(**_summary(exposure, app, submitted_at, submitted_by, assessment)))
    return out


@router.get("/exposures/{exposure_id}", response_model=ExposureDetail)
async def get_exposure(exposure_id: str, request: Request) -> ExposureDetail:
    async with _session_factory(request)() as session:
        return await _detail(session, exposure_id)


def _not_found() -> HTTPException:
    return HTTPException(status_code=404, detail={"message": "exposure not found"})


async def _detail(session: AsyncSession, exposure_id: str) -> ExposureDetail:
    """The exposure as the workspace shows it, or 404."""
    row = (
        await session.execute(_with_submission().where(ExposureRow.id == exposure_id))
    ).first()
    if row is None:
        raise _not_found()
    exposure, app, submitted_at, submitted_by = row
    loaded = await load_services(session, exposure.scan_id)
    groups = await exposures.load_groups(session, exposure.id)
    group_of = (await exposures.load_group_members(session, [exposure.id]))[exposure.id]
    registry = await exposures.load_registry(session)
    deploying = (await exposures.load_deploying(session, [exposure.app_id]))[exposure.app_id]
    supersedes = (
        await session.execute(
            select(ExposureRow.id).where(ExposureRow.superseded_by_id == exposure.id)
        )
    ).scalar_one_or_none()

    assessment = exposures.assess(
        services=[service for service, *_ in loaded],
        found_by={
            service.id: [finding.scanner for finding, _ in findings]
            for service, _, findings, _, _ in loaded
        },
        group_of=group_of,
        registry=exposures.registry_for(registry, exposure.id),
        scan_entries={
            service.id: entry for service, _, _, _, entry in loaded if entry is not None
        },
        deploying=[d for d in deploying if d != exposure.id],
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
        plan=exposure.plan,
        plan_hash=exposure.plan_hash,
        plan_version=exposure.plan_version,
        confirmed_by=exposure.confirmed_by,
        confirmed_at=_isoformat(exposure.confirmed_at),
        failed=(
            ExposureFailure(
                phase=exposure.failed_phase, step=exposure.failed_step, message=exposure.failed_message
            )
            if exposure.failed_phase
            else None
        ),
        deployment=exposure.deployment,
        deployed_at=_isoformat(exposure.deployed_at),
    )


def _conflict(exposure: ExposureRow, message: str) -> HTTPException:
    """409, with what the console needs to reload: the current status and version."""
    return HTTPException(
        status_code=409,
        detail={"message": message, "status": exposure.status, "version": exposure.version},
    )


@router.put("/exposures/{exposure_id}/groups", response_model=ExposureDetail)
async def save_groups(exposure_id: str, body: SaveGroupingRequest, request: Request) -> ExposureDetail:
    """Replace the grouping. Allowed while the exposure is grouping, planning
    or awaiting confirmation; moves it to grouping, dropping any plan, and
    increments its version. Refused with 409 when `version` is not the
    current one, and with 422 and an error per service when the grouping
    does not put each service that needs a VIP in exactly one group."""
    async with _session_factory(request)() as session:
        exposure = (
            await session.execute(
                select(ExposureRow).where(ExposureRow.id == exposure_id).with_for_update()
            )
        ).scalar_one_or_none()
        if exposure is None:
            raise _not_found()
        if exposure.status not in [s.value for s in exposures.EDITABLE_STATUSES]:
            raise _conflict(exposure, f"the grouping of a {exposure.status} exposure cannot change")
        if body.version != exposure.version:
            raise _conflict(
                exposure,
                f"the exposure is at version {exposure.version}; this grouping was made against version {body.version}",
            )

        services = (await exposures.load_scan_services(session, [exposure.scan_id]))[exposure.scan_id]
        assessment = exposures.assess(
            services=services,
            found_by={},
            group_of={},
            registry=await exposures.load_registry(session),
        )
        groups = [group.service_ids for group in body.groups]
        errors = exposures.validate_grouping(groups, services, assessment)
        if errors:
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "each service that needs a VIP must be in exactly one group",
                    "errors": [_notice(error).model_dump() for error in errors],
                },
            )
        await exposures.save_grouping(
            session, exposure, [(group.id, group.service_ids) for group in body.groups], _STUB_USER.username
        )
        await session.commit()
        return await _detail(session, exposure_id)


@router.get("/exposures/{exposure_id}/events")
async def exposure_events(exposure_id: str, request: Request):
    """The exposure's event log as a server-sent event stream: every admin
    action, and every step the agent reports. Resumes after `Last-Event-ID`.
    A closed exposure's stream replays and ends; an open one's ends after the
    event that closes it."""
    factory = _session_factory(request)
    bus = request.app.state.event_bus

    async with factory() as session:
        exposure = await session.get(ExposureRow, exposure_id)
    if exposure is None:
        raise HTTPException(status_code=404, detail={"message": "exposure not found"})

    last_event_id = request.headers.get("Last-Event-ID")
    try:
        start_seq = int(last_event_id) + 1 if last_event_id else 0
    except (TypeError, ValueError):
        start_seq = 0

    closed = exposure.status in [s.value for s in CLOSED_EXPOSURE_STATUSES]

    # Subscribed before the first read, so no wake-up is missed in between.
    wake = asyncio.Event()
    if not closed:
        bus.subscribe_exposure(exposure_id, wake)

    async def event_gen():
        next_seq = start_seq
        try:
            while True:
                wake.clear()
                async with factory() as session:
                    rows = await exposures.replay_events(session, exposure_id, next_seq)
                for row in rows:
                    yield {"id": str(row.seq), "data": json.dumps(exposures.event_to_dict(row))}
                    next_seq = row.seq + 1
                    if row.type in exposures.TERMINAL_EVENTS:
                        return
                if closed or await request.is_disconnected():
                    return
                try:
                    await asyncio.wait_for(wake.wait(), timeout=15.0)
                except asyncio.TimeoutError:
                    yield {"comment": "keepalive"}
        finally:
            if not closed:
                bus.unsubscribe_exposure(exposure_id, wake)

    return EventSourceResponse(event_gen())


async def _locked(session: AsyncSession, exposure_id: str) -> ExposureRow:
    exposure = (
        await session.execute(select(ExposureRow).where(ExposureRow.id == exposure_id).with_for_update())
    ).scalar_one_or_none()
    if exposure is None:
        raise _not_found()
    return exposure


async def _act(request: Request, exposure_id: str, action) -> ExposureDetail:
    """Run a status change in one transaction with the event that records it,
    and return the exposure as it now stands."""
    async with _session_factory(request)() as session:
        exposure = await _locked(session, exposure_id)
        try:
            await action(session, exposure)
        except exposure_lifecycle.Refused as refused:
            raise HTTPException(status_code=refused.status_code, detail=refused.detail)
        await session.commit()
        return await _detail(session, exposure_id)


@router.post("/exposures/{exposure_id}/plan", response_model=ExposureDetail)
async def request_plan(exposure_id: str, body: VersionRequest, request: Request) -> ExposureDetail:
    """`grouping` to `planning`. Refused with 409, and the reasons as
    `blocked_by`, while anything blocks planning."""
    return await _act(request, exposure_id, lambda s, e: exposure_lifecycle.request_plan(
        s, e, body.version, _STUB_USER.username
    ))


@router.post("/exposures/{exposure_id}/confirm", response_model=ExposureDetail)
async def confirm_plan(exposure_id: str, body: ConfirmRequest, request: Request) -> ExposureDetail:
    """`awaiting_confirmation` to `deploying`, for the plan with `plan_hash`.
    Any admin may confirm, including the one who asked for the plan."""
    return await _act(request, exposure_id, lambda s, e: exposure_lifecycle.confirm(
        s, e, body.version, body.plan_hash, _STUB_USER.username
    ))


@router.post("/exposures/{exposure_id}/retry", response_model=ExposureDetail)
async def retry_exposure(exposure_id: str, body: VersionRequest, request: Request) -> ExposureDetail:
    """`failed` back to the phase that failed."""
    return await _act(request, exposure_id, lambda s, e: exposure_lifecycle.retry(
        s, e, body.version, _STUB_USER.username
    ))


@router.post("/exposures/{exposure_id}/cancel", response_model=ExposureDetail)
async def cancel_exposure(exposure_id: str, body: VersionRequest, request: Request) -> ExposureDetail:
    """To `cancelled` if never planned, otherwise to `cancelling` for the
    agent to release what the exposure holds. Refused while deploying."""
    return await _act(request, exposure_id, lambda s, e: exposure_lifecycle.cancel(
        s, e, body.version, _STUB_USER.username
    ))
