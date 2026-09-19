import uuid
from typing import Dict, List, Tuple

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .db import AppRow, FindingRow, ScanRow, SubmissionRow
from .models import (
    AppSummary,
    AuthMethod,
    AuthMethodChange,
    CreateAppRequest,
    ExclusionChange,
    Finding,
    ScanDiff,
    ScanSummary,
    Severity,
)
from .serialize import app_to_summary, finding_to_schema, scan_to_summary

router = APIRouter()


def _session_factory(request: Request) -> async_sessionmaker[AsyncSession]:
    return request.app.state.session_factory


def _blocker_count_subq():
    return (
        select(
            FindingRow.scan_id.label("scan_id"),
            func.coalesce(
                func.sum(
                    case(
                        (
                            (FindingRow.severity == Severity.blocker.value)
                            & (FindingRow.excluded.is_(False)),
                            1,
                        ),
                        else_=0,
                    )
                ),
                0,
            ).label("blocker_count"),
        )
        .group_by(FindingRow.scan_id)
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
                FindingRow.scan_id.label("scan_id"),
                func.count(FindingRow.id).label("finding_count"),
                func.coalesce(
                    func.sum(
                        case(
                            (
                                (FindingRow.severity == Severity.blocker.value)
                                & (FindingRow.excluded.is_(False)),
                                1,
                            ),
                            else_=0,
                        )
                    ),
                    0,
                ).label("blocker_count"),
            )
            .group_by(FindingRow.scan_id)
            .subquery()
        )
        # submissions.scan_id is UNIQUE — direct join, no aggregation needed.
        stmt = (
            select(
                ScanRow,
                func.coalesce(agg.c.blocker_count, 0),
                func.coalesce(agg.c.finding_count, 0),
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
        for scan, blocker_count, finding_count, submitted_at, submitted_by in result.all():
            out.append(
                scan_to_summary(
                    scan,
                    blocker_count=int(blocker_count or 0),
                    finding_count=int(finding_count or 0),
                    submitted_at=submitted_at,
                    submitted_by=submitted_by,
                )
            )
        return out


async def _findings_by_origin(session, scan_id: str) -> Dict[Tuple[str, str, int], Finding]:
    # Keyed on the finding's identity, the (scheme, host, port) origin.
    rows = (
        await session.execute(select(FindingRow).where(FindingRow.scan_id == scan_id))
    ).scalars().all()
    return {(r.scheme, r.host, r.port): finding_to_schema(r) for r in rows}


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
        a = await _findings_by_origin(session, from_id)
        b = await _findings_by_origin(session, to_id)

    added: list[Finding] = [f for origin, f in b.items() if origin not in a]
    removed: list[Finding] = [f for origin, f in a.items() if origin not in b]
    exclusion_changes: list[ExclusionChange] = []
    auth_method_changes: list[AuthMethodChange] = []
    for origin, b_finding in b.items():
        a_finding = a.get(origin)
        if not a_finding:
            continue
        scheme, host, port = origin
        if a_finding.excluded != b_finding.excluded:
            exclusion_changes.append(
                ExclusionChange(
                    id=b_finding.id,
                    scheme=scheme,
                    host=host,
                    port=port,
                    before=a_finding.excluded,
                    after=b_finding.excluded,
                )
            )
        if a_finding.auth_method != b_finding.auth_method:
            auth_method_changes.append(
                AuthMethodChange(
                    id=b_finding.id,
                    scheme=scheme,
                    host=host,
                    port=port,
                    before=AuthMethod(a_finding.auth_method),
                    after=AuthMethod(b_finding.auth_method),
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
