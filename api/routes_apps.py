import uuid
from typing import Dict, List, Tuple

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from core.db import AppRow, ScanRow, ServiceRow, SubmissionRow, load_services
from core.enums import AuthMethod, Severity

from .models import (
    AppSummary,
    AuthMethodChange,
    CreateAppRequest,
    ExclusionChange,
    ScanDiff,
    ScanSummary,
    Service,
)
from .serialize import app_to_summary, scan_to_summary, service_to_schema

router = APIRouter()


def _session_factory(request: Request) -> async_sessionmaker[AsyncSession]:
    return request.app.state.session_factory


def _blocker_count_subq():
    return (
        select(
            ServiceRow.scan_id.label("scan_id"),
            func.coalesce(
                func.sum(
                    case(
                        (
                            (ServiceRow.severity == Severity.blocker.value)
                            & (ServiceRow.excluded.is_(False)),
                            1,
                        ),
                        else_=0,
                    )
                ),
                0,
            ).label("blocker_count"),
        )
        .group_by(ServiceRow.scan_id)
        .subquery()
    )


@router.get("/apps", response_model=List[AppSummary])
async def list_apps(request: Request) -> List[AppSummary]:
    factory = _session_factory(request)
    async with factory() as session:
        # Most recent scan per app, by started_at desc.
        latest_subq = (
            select(
                ScanRow.app_id.label("app_id"),
                func.max(ScanRow.started_at).label("latest_started_at"),
            )
            .group_by(ScanRow.app_id)
            .subquery()
        )
        blockers = _blocker_count_subq()
        stmt = (
            select(
                AppRow,
                ScanRow,
                func.coalesce(blockers.c.blocker_count, 0),
            )
            .outerjoin(latest_subq, latest_subq.c.app_id == AppRow.id)
            .outerjoin(
                ScanRow,
                (ScanRow.app_id == AppRow.id)
                & (ScanRow.started_at == latest_subq.c.latest_started_at),
            )
            .outerjoin(blockers, blockers.c.scan_id == ScanRow.id)
            .order_by(AppRow.created_at.desc())
        )
        result = await session.execute(stmt)
        out: list[AppSummary] = []
        for app, scan, blocker_count in result.all():
            out.append(
                app_to_summary(
                    app,
                    last_scan=scan,
                    last_scan_blocker_count=int(blocker_count or 0),
                )
            )
        return out


@router.post("/apps", response_model=AppSummary, status_code=201)
async def create_app(body: CreateAppRequest, request: Request) -> AppSummary:
    factory = _session_factory(request)
    app_id = "app_" + uuid.uuid4().hex[:10]

    async with factory() as session:
        app = AppRow(
            id=app_id,
            name=body.name,
            url=body.url,
            owner_ad_group=body.owner_ad_group,
        )
        session.add(app)
        await session.commit()
        await session.refresh(app)

    return app_to_summary(app, last_scan=None, last_scan_blocker_count=0)


@router.get("/apps/{app_id}/scans", response_model=List[ScanSummary])
async def list_app_scans(app_id: str, request: Request) -> List[ScanSummary]:
    factory = _session_factory(request)
    async with factory() as session:
        agg = (
            select(
                ServiceRow.scan_id.label("scan_id"),
                func.count(ServiceRow.id).label("service_count"),
                func.coalesce(
                    func.sum(
                        case(
                            (
                                (ServiceRow.severity == Severity.blocker.value)
                                & (ServiceRow.excluded.is_(False)),
                                1,
                            ),
                            else_=0,
                        )
                    ),
                    0,
                ).label("blocker_count"),
            )
            .group_by(ServiceRow.scan_id)
            .subquery()
        )
        # submissions.scan_id is UNIQUE — direct join, no aggregation needed.
        stmt = (
            select(
                ScanRow,
                func.coalesce(agg.c.blocker_count, 0),
                func.coalesce(agg.c.service_count, 0),
                SubmissionRow.submitted_at,
                SubmissionRow.submitted_by,
            )
            .outerjoin(agg, agg.c.scan_id == ScanRow.id)
            .outerjoin(SubmissionRow, SubmissionRow.scan_id == ScanRow.id)
            .where(ScanRow.app_id == app_id)
            .order_by(ScanRow.started_at.desc())
        )
        result = await session.execute(stmt)
        out: list[ScanSummary] = []
        for scan, blocker_count, service_count, submitted_at, submitted_by in result.all():
            out.append(
                scan_to_summary(
                    scan,
                    blocker_count=int(blocker_count or 0),
                    service_count=int(service_count or 0),
                    submitted_at=submitted_at,
                    submitted_by=submitted_by,
                )
            )
        return out


async def _services_by_origin(session, scan_id: str) -> Dict[Tuple[str, str, int], Service]:
    # Keyed on the service's identity, the (scheme, host, port) origin.
    return {
        (service.scheme, service.host, service.port): service_to_schema(service, evidence, findings)
        for service, evidence, findings in await load_services(session, scan_id)
    }


@router.get("/apps/{app_id}/diff", response_model=ScanDiff)
async def app_diff(
    app_id: str,
    request: Request,
    from_: str | None = None,
    to: str | None = None,
) -> ScanDiff:
    # `from` is reserved in Python, so accept it under an alias.
    qp = request.query_params
    from_id = from_ or qp.get("from") or ""
    to_id = to or qp.get("to") or ""
    if not from_id or not to_id:
        raise HTTPException(status_code=400, detail={"message": "from and to are required"})

    factory = _session_factory(request)
    async with factory() as session:
        for scan_id in (from_id, to_id):
            scan = await session.get(ScanRow, scan_id)
            if not scan or scan.app_id != app_id:
                raise HTTPException(
                    status_code=404,
                    detail={"message": f"scan {scan_id} not found for app {app_id}"},
                )
        a = await _services_by_origin(session, from_id)
        b = await _services_by_origin(session, to_id)

    added: list[Service] = [s for origin, s in b.items() if origin not in a]
    removed: list[Service] = [s for origin, s in a.items() if origin not in b]
    exclusion_changes: list[ExclusionChange] = []
    auth_method_changes: list[AuthMethodChange] = []
    for origin, b_service in b.items():
        a_service = a.get(origin)
        if not a_service:
            continue
        scheme, host, port = origin
        if a_service.excluded != b_service.excluded:
            exclusion_changes.append(
                ExclusionChange(
                    id=b_service.id,
                    scheme=scheme,
                    host=host,
                    port=port,
                    before=a_service.excluded,
                    after=b_service.excluded,
                )
            )
        if a_service.auth_method != b_service.auth_method:
            auth_method_changes.append(
                AuthMethodChange(
                    id=b_service.id,
                    scheme=scheme,
                    host=host,
                    port=port,
                    before=AuthMethod(a_service.auth_method),
                    after=AuthMethod(b_service.auth_method),
                )
            )

    return ScanDiff(
        from_scan_id=from_id,
        to_scan_id=to_id,
        added=added,
        removed=removed,
        exclusion_changes=exclusion_changes,
        auth_method_changes=auth_method_changes,
    )
