import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import case, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from config_tracer.settings import ScanSettings
from core import jobs
from core.db import (
    AppRow,
    ScanJobRow,
    ScanRow,
    ServiceRow,
    SubmissionRow,
    UrlRow,
    load_services,
)
from core.enums import AuthMethod, JobStatus, Scanner, ScanStatus, Severity
from core.events import emit_event
from core.translate import severity_for

from .models import (
    CreateScanRequest,
    CreateScanResponse,
    PatchServiceRequest,
    ScanDetail,
    ScanSummary,
    Service,
    SubmitScanResponse,
    Url,
)
from .routes_me import _STUB_USER
from .serialize import scan_to_detail, scan_to_summary, service_to_schema, url_to_schema

logger = logging.getLogger(__name__)

router = APIRouter()

# The auth methods a manual correction may replace, and so never set: the ones
# that mean the scanners could not tell what the service takes.
_FILL_IN_AUTH_METHODS = (
    AuthMethod.unknown.value,
    AuthMethod.no_response.value,
    AuthMethod.dns_failed.value,
)


def _session_factory(request: Request) -> async_sessionmaker[AsyncSession]:
    return request.app.state.session_factory


def _tracer_settings(request: Request) -> ScanSettings:
    return request.app.state.tracer_settings


def _summary_aggregates_subq():
    return (
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
            func.count(func.distinct(ServiceRow.auth_method)).label("auth_count"),
        )
        .group_by(ServiceRow.scan_id)
        .subquery()
    )


# Direct outerjoin works since submissions.scan_id is UNIQUE — at most one
# submission per scan. No aggregation needed.


async def _latest_completed_scan_id(session, app_id: str) -> str | None:
    """The newest-by-started_at completed scan for an app, or None.

    Used by both submit (for eligibility) and patch_service (for the editability
    freeze). Failed/cancelled/running/queued scans don't count — they have no
    services to act on and shouldn't shadow an earlier valid completed scan.
    Nor does a partial scan: a scanner's results are missing from its services.
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
                func.coalesce(agg.c.service_count, 0).label("service_count"),
                SubmissionRow.submitted_at,
                SubmissionRow.submitted_by,
            )
            .outerjoin(agg, agg.c.scan_id == ScanRow.id)
            .outerjoin(SubmissionRow, SubmissionRow.scan_id == ScanRow.id)
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


@router.get("/scans/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: str, request: Request) -> ScanDetail:
    factory = _session_factory(request)
    async with factory() as session:
        agg = _summary_aggregates_subq()
        stmt = (
            select(
                ScanRow,
                func.coalesce(agg.c.blocker_count, 0),
                func.coalesce(agg.c.service_count, 0),
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
        scan, blocker_count, service_count, auth_count, submitted_at, submitted_by = row
        jobs = (
            await session.execute(
                select(ScanJobRow)
                .where(ScanJobRow.scan_id == scan_id)
                .order_by(ScanJobRow.scanner)
            )
        ).scalars().all()
        return scan_to_detail(
            scan,
            blocker_count=int(blocker_count or 0),
            service_count=int(service_count or 0),
            auth_methods=int(auth_count or 0),
            jobs=jobs,
            submitted_at=submitted_at,
            submitted_by=submitted_by,
        )


@router.get("/scans/{scan_id}/services", response_model=List[Service])
async def list_services(scan_id: str, request: Request) -> List[Service]:
    factory = _session_factory(request)
    async with factory() as session:
        scan = await session.get(ScanRow, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail={"message": "scan not found"})
        return [service_to_schema(*loaded) for loaded in await load_services(session, scan_id)]


@router.get("/scans/{scan_id}/services/{service_id}/urls", response_model=List[Url])
async def list_service_urls(
    scan_id: str, service_id: str, request: Request, scanner: Optional[Scanner] = None
) -> List[Url]:
    """The service's urls from both scanners, or with `?scanner=` only that one's."""
    factory = _session_factory(request)
    async with factory() as session:
        service = await session.get(ServiceRow, service_id)
        if not service or service.scan_id != scan_id:
            raise HTTPException(status_code=404, detail={"message": "service not found"})
        # Query the table directly rather than touching service.urls: a lazy
        # relationship load inside an async session raises MissingGreenlet.
        # Ids are random, so sort by (url, method) for a stable listing.
        stmt = select(UrlRow).where(UrlRow.service_id == service_id)
        if scanner is not None:
            stmt = stmt.where(UrlRow.scanner == scanner.value)
        rows = (await session.execute(stmt.order_by(UrlRow.url, UrlRow.method))).scalars().all()
        return [url_to_schema(r) for r in rows]


@router.post("/scans", response_model=CreateScanResponse)
async def create_scan(body: CreateScanRequest, request: Request) -> CreateScanResponse:
    factory = _session_factory(request)

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
                status=ScanStatus.queued.value,
                started_at=started_at,
                started_by=started_by,
            )
        )
        # One job per scanner, each with its settings as they stand now.
        job_settings = {
            # None leaves the depth to the worker's config.json.
            Scanner.interceptor: {"max_depth": body.max_depth},
            Scanner.tracer: _tracer_settings(request).model_dump(mode="json"),
        }
        for scanner, settings in job_settings.items():
            session.add(
                ScanJobRow(
                    id=uuid.uuid4().hex,
                    scan_id=scan_id,
                    scanner=scanner.value,
                    status=JobStatus.queued.value,
                    settings=settings,
                    created_at=started_at,
                )
            )
        # Same transaction as the scan, so no event can precede it.
        await emit_event(session, scan_id, "scan_started", {"url": start_url, "name": name})
        # Committing the queued jobs is the whole enqueue; a worker of each scanner claims its own.
        await session.commit()

    return CreateScanResponse(scan_id=scan_id)


@router.patch("/scans/{scan_id}/services/{service_id}", response_model=Service)
async def patch_service(
    scan_id: str,
    service_id: str,
    body: PatchServiceRequest,
    request: Request,
) -> Service:
    factory = _session_factory(request)
    async with factory() as session:
        service = await session.get(ServiceRow, service_id)
        if not service or service.scan_id != scan_id:
            raise HTTPException(status_code=404, detail={"message": "service not found"})
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
            # scanners couldn't classify ("unknown"), never got an answer from
            # ("no_response") or couldn't resolve ("dns_failed") — never to
            # override an auto-detected method, and never back to any of them.
            # "other" (a real but unnamed challenge) counts as classified, so
            # it stays locked here too.
            if service.auth_method not in _FILL_IN_AUTH_METHODS:
                raise HTTPException(
                    status_code=409,
                    detail={"message": "auth method can only be set manually while it is unknown, no_response or dns_failed"},
                )
            if body.auth_method.value in _FILL_IN_AUTH_METHODS:
                raise HTTPException(
                    status_code=422,
                    detail={"message": f"cannot set auth method to {body.auth_method.value}"},
                )
            service.auth_method = body.auth_method.value
            # Severity is derived from the auth method, so re-derive it using
            # the same mapping the crawler uses (e.g. ntlm -> blocker).
            service.severity = severity_for(body.auth_method).value

        if body.excluded is not None:
            service.excluded = body.excluded

        await session.commit()
        await session.refresh(service)
        # The scanners' findings are untouched: only the combined verdict was filled in.
        [loaded] = await load_services(session, scan_id, service_id=service_id)
        return service_to_schema(*loaded)


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
                .select_from(ServiceRow)
                .where(
                    ServiceRow.scan_id == scan_id,
                    ServiceRow.severity == Severity.blocker.value,
                    ServiceRow.excluded.is_(False),
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
    factory = _session_factory(request)

    async with factory() as session:
        scan = await session.get(ScanRow, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail={"message": "scan not found"})

        # Queued jobs end here, and the scan with them if none is running. A
        # worker running one polls the request, then ends its job; the scan
        # ends, with scan_failed, when the last of them has.
        await jobs.cancel(session, scan_id)
        await session.commit()

    return Response(status_code=status.HTTP_204_NO_CONTENT)
