import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import case, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .db import AppRow, FindingRow, ScanRow, SubmissionRow
from .models import (
    AuthMethod,
    CreateScanRequest,
    CreateScanResponse,
    Finding,
    PatchFindingRequest,
    ScanDetail,
    ScanSummary,
    Severity,
    SubmitScanResponse,
)
from .routes_me import _STUB_USER
from .serialize import finding_to_schema, scan_to_detail, scan_to_summary
from .service import run_scrape_job
from .translate import severity_for

logger = logging.getLogger(__name__)

router = APIRouter()


def _session_factory(request: Request) -> async_sessionmaker[AsyncSession]:
    return request.app.state.session_factory


def _summary_aggregates_subq():
    return (
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
            func.count(func.distinct(FindingRow.auth_method)).label("auth_count"),
        )
        .group_by(FindingRow.scan_id)
        .subquery()
    )


# Direct outerjoin works since submissions.scan_id is UNIQUE — at most one
# submission per scan. No aggregation needed.


async def _latest_completed_scan_id(session, app_id: str) -> str | None:
    """The newest-by-started_at completed scan for an app, or None.

    Used by both submit (for eligibility) and patch_finding (for the editability
    freeze). Failed/cancelled/running/queued scans don't count — they have no
    actionable findings and shouldn't shadow an earlier valid completed scan.
    """
    return (
        await session.execute(
            select(ScanRow.id)
            .where(ScanRow.app_id == app_id, ScanRow.status == "completed")
            .order_by(ScanRow.started_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


@router.get("/scans", response_model=List[ScanSummary])
async def list_scans(request: Request) -> List[ScanSummary]:
    factory = _session_factory(request)
    async with factory() as session:
        agg = _summary_aggregates_subq()
        stmt = (
            select(
                ScanRow,
                func.coalesce(agg.c.blocker_count, 0).label("blocker_count"),
                func.coalesce(agg.c.finding_count, 0).label("finding_count"),
                SubmissionRow.submitted_at,
                SubmissionRow.submitted_by,
            )
            .outerjoin(agg, agg.c.scan_id == ScanRow.id)
            .outerjoin(SubmissionRow, SubmissionRow.scan_id == ScanRow.id)
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


@router.get("/scans/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: str, request: Request) -> ScanDetail:
    factory = _session_factory(request)
    async with factory() as session:
        agg = _summary_aggregates_subq()
        stmt = (
            select(
                ScanRow,
                func.coalesce(agg.c.blocker_count, 0),
                func.coalesce(agg.c.finding_count, 0),
                func.coalesce(agg.c.auth_count, 0),
                SubmissionRow.submitted_at,
                SubmissionRow.submitted_by,
            )
            .outerjoin(agg, agg.c.scan_id == ScanRow.id)
            .outerjoin(SubmissionRow, SubmissionRow.scan_id == ScanRow.id)
            .where(ScanRow.id == scan_id)
        )
        row = (await session.execute(stmt)).first()
        if not row:
            raise HTTPException(status_code=404, detail={"message": "scan not found"})
        (
            scan,
            blocker_count,
            finding_count,
            auth_count,
            submitted_at,
            submitted_by,
        ) = row
        return scan_to_detail(
            scan,
            blocker_count=int(blocker_count or 0),
            finding_count=int(finding_count or 0),
            # An external service is one origin, and a scan holds exactly one
            # finding per origin (uq_findings_scan_origin), so the two counts
            # coincide. Kept as its own field: it is the stat the FE shows, not a
            # row count, and it includes excluded findings.
            external_services=int(finding_count or 0),
            auth_methods=int(auth_count or 0),
            submitted_at=submitted_at,
            submitted_by=submitted_by,
        )


@router.get("/scans/{scan_id}/findings", response_model=List[Finding])
async def list_findings(scan_id: str, request: Request) -> List[Finding]:
    factory = _session_factory(request)
    async with factory() as session:
        scan = await session.get(ScanRow, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail={"message": "scan not found"})
        rows = (
            await session.execute(
                select(FindingRow)
                .where(FindingRow.scan_id == scan_id)
                .order_by(FindingRow.host, FindingRow.port, FindingRow.scheme)
            )
        ).scalars().all()
        return [finding_to_schema(r) for r in rows]


@router.post("/scans", response_model=CreateScanResponse)
async def create_scan(body: CreateScanRequest, request: Request) -> CreateScanResponse:
    app_state = request.app.state
    factory = _session_factory(request)
    event_bus = app_state.event_bus

    scan_id = uuid.uuid4().hex
    started_at = datetime.now(timezone.utc)
    started_by = _STUB_USER.username

    async with factory() as session:
        existing_app = await session.get(AppRow, body.app_id)
        if not existing_app:
            raise HTTPException(status_code=404, detail={"message": "app not found"})
        # The scan always targets the app's own URL — it's no longer supplied per
        # scan. Apps are created with a required URL, but guard for legacy rows
        # that predate that rule so we never start a scrape without a start URL.
        if not existing_app.url:
            raise HTTPException(
                status_code=422,
                detail={"message": "app has no URL configured; cannot start a scan"},
            )
        name = existing_app.name
        start_url = existing_app.url
        session.add(
            ScanRow(
                id=scan_id,
                app_id=body.app_id,
                name=name,
                url=start_url,
                status="queued",
                started_at=started_at,
                started_by=started_by,
                max_depth=body.max_depth,
                pages_crawled=0,
            )
        )
        await session.commit()

    # Persist the seed scan_started event before responding so an immediate SSE
    # GET sees at least one event.
    await event_bus.emit(scan_id, "scan_started", {"url": start_url, "name": name})

    task = asyncio.create_task(
        run_scrape_job(
            scan_id=scan_id,
            base_config=app_state.base_config,
            start_url=start_url,
            max_depth=body.max_depth,
            semaphore=app_state.semaphore,
            session_factory=factory,
            event_bus=event_bus,
        ),
        name=f"scan-{scan_id}",
    )
    app_state.scan_tasks[scan_id] = task
    app_state.background_tasks.add(task)

    def _cleanup(_t: asyncio.Task) -> None:
        app_state.background_tasks.discard(_t)
        app_state.scan_tasks.pop(scan_id, None)

    task.add_done_callback(_cleanup)

    return CreateScanResponse(scan_id=scan_id)


@router.patch("/scans/{scan_id}/findings/{finding_id}", response_model=Finding)
async def patch_finding(
    scan_id: str,
    finding_id: str,
    body: PatchFindingRequest,
    request: Request,
) -> Finding:
    factory = _session_factory(request)
    async with factory() as session:
        finding = await session.get(FindingRow, finding_id)
        if not finding or finding.scan_id != scan_id:
            raise HTTPException(status_code=404, detail={"message": "finding not found"})
        scan = await session.get(ScanRow, scan_id)
        # Editable iff this is the latest completed scan AND has never been
        # submitted. Two distinct error messages so the UI can tell the user
        # *why* edits are blocked.
        already_submitted = (
            await session.execute(
                select(func.count())
                .select_from(SubmissionRow)
                .where(SubmissionRow.scan_id == scan_id)
            )
        ).scalar_one()
        if already_submitted:
            raise HTTPException(
                status_code=409,
                detail={"message": "this scan is submitted and locked"},
            )
        latest_completed_id = await _latest_completed_scan_id(session, scan.app_id)
        if latest_completed_id != scan_id:
            raise HTTPException(
                status_code=409,
                detail={"message": "only the latest completed scan can be edited"},
            )

        if body.auth_method is not None:
            # Manual auth correction is allowed only as a fill-in for what the
            # scraper couldn't classify — never to override an auto-detected
            # method, and never back to "unknown". "other" (a real but unnamed
            # challenge) counts as classified, so it stays locked here too.
            if finding.auth_method != AuthMethod.unknown.value:
                raise HTTPException(
                    status_code=409,
                    detail={"message": "auth method can only be set manually while it is unknown"},
                )
            if body.auth_method == AuthMethod.unknown:
                raise HTTPException(
                    status_code=422,
                    detail={"message": "cannot set auth method to unknown"},
                )
            finding.auth_method = body.auth_method.value
            # Severity is derived from the auth method, so re-derive it using
            # the same mapping the scraper uses (e.g. ntlm -> blocker).
            finding.severity = severity_for(body.auth_method).value

        if body.excluded is not None:
            finding.excluded = body.excluded

        await session.commit()
        await session.refresh(finding)
        return finding_to_schema(finding)


@router.post("/scans/{scan_id}/submit", response_model=SubmitScanResponse)
async def submit_scan(scan_id: str, request: Request) -> SubmitScanResponse:
    factory = _session_factory(request)
    async with factory() as session:
        scan = await session.get(ScanRow, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail={"message": "scan not found"})

        # Status check first so a non-completed scan always gets the most
        # specific error, regardless of what other scans exist for the app.
        if scan.status != "completed":
            raise HTTPException(
                status_code=409,
                detail={"message": f"scan is {scan.status}, only completed scans can be submitted"},
            )

        latest_completed_id = await _latest_completed_scan_id(session, scan.app_id)
        if latest_completed_id != scan_id:
            raise HTTPException(
                status_code=409,
                detail={"message": "only the latest completed scan can be submitted"},
            )

        # A scan can only be submitted once. Re-submitting the same scan_id is a
        # no-op semantically (it's already the canonical version) and would only
        # create a duplicate SubmissionRow.
        already_submitted = (
            await session.execute(
                select(func.count())
                .select_from(SubmissionRow)
                .where(SubmissionRow.scan_id == scan_id)
            )
        ).scalar_one()
        if already_submitted:
            raise HTTPException(
                status_code=409,
                detail={"message": "this scan has already been submitted"},
            )

        unresolved_blockers = (
            await session.execute(
                select(func.count())
                .select_from(FindingRow)
                .where(
                    FindingRow.scan_id == scan_id,
                    FindingRow.severity == Severity.blocker.value,
                    FindingRow.excluded.is_(False),
                )
            )
        ).scalar_one()
        if unresolved_blockers:
            raise HTTPException(
                status_code=409,
                detail={"message": f"{unresolved_blockers} unresolved blocker(s) remain"},
            )

        # Load AppRow *before* staging the new SubmissionRow — otherwise the
        # session.get triggers an autoflush that hits the UNIQUE constraint
        # outside our commit's try/except.
        app_row = await session.get(AppRow, scan.app_id)
        submission_id = "sub_" + uuid.uuid4().hex[:10]
        session.add(
            SubmissionRow(
                id=submission_id,
                scan_id=scan_id,
                submitted_by=_STUB_USER.username,
            )
        )
        # Promote this scan to the app's canonical "current version".
        if app_row is not None:
            app_row.current_scan_id = scan_id
        try:
            await session.commit()
        except IntegrityError:
            # Lost a race: another submit committed first and the unique
            # constraint on submissions.scan_id rejected ours. The in-transaction
            # `already_submitted` check above can't catch this — only the DB can.
            await session.rollback()
            raise HTTPException(
                status_code=409,
                detail={"message": "this scan has already been submitted"},
            )
        return SubmitScanResponse(submission_id=submission_id)


@router.post("/scans/{scan_id}/cancel", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_scan(scan_id: str, request: Request) -> Response:
    app_state = request.app.state
    factory = _session_factory(request)

    async with factory() as session:
        scan = await session.get(ScanRow, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail={"message": "scan not found"})

    task = app_state.scan_tasks.get(scan_id)
    if task and not task.done():
        task.cancel()
    else:
        # Task already gone — record a cancellation manually.
        async with factory() as session:
            scan = await session.get(ScanRow, scan_id)
            if scan and scan.status in ("queued", "running"):
                scan.status = "cancelled"
                scan.completed_at = datetime.now(timezone.utc)
                scan.error = "cancelled"
                await session.commit()
        await app_state.event_bus.emit(scan_id, "scan_failed", {"reason": "cancelled"})

    return Response(status_code=status.HTTP_204_NO_CONTENT)
