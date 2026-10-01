"""Helpers that turn ORM rows into the shapes the frontend expects."""
from datetime import datetime, timezone
from typing import Optional, Sequence, Tuple

from core.db import AppRow, ScanJobRow, ScanRow, ServiceFindingRow, ServiceRow, UrlRow
from core.enums import AuthMethod, JobStatus, Scanner, Severity
from core.translate import severity_for

from .models import (
    AppSummary,
    ExposureState,
    Finding,
    ScanDetail,
    ScanJob,
    ScanStatus,
    ScanSummary,
    Service,
    Url,
)


def _isoformat(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def finding_to_schema(row: ServiceFindingRow, evidence: UrlRow | None) -> Finding:
    auth_method = AuthMethod(row.auth_method)
    return Finding(
        scanner=Scanner(row.scanner),
        auth_method=auth_method,
        # Not stored: a finding's severity is its method's.
        severity=severity_for(auth_method),
        evidence=url_to_schema(evidence) if evidence is not None else None,
    )


def service_to_schema(
    row: ServiceRow,
    evidence: UrlRow | None,
    findings: Sequence[Tuple[ServiceFindingRow, UrlRow | None]],
) -> Service:
    """`evidence` is the url row `row.evidence_url_id` points at, or None when it
    points nowhere. `findings` is each scanner's finding for the service with
    the url row its own evidence_url_id points at. The caller loads them
    (db.load_services)."""
    return Service(
        id=row.id,
        scheme=row.scheme,
        host=row.host,
        port=row.port,
        auth_method=AuthMethod(row.auth_method),
        severity=Severity(row.severity),
        request_count=row.request_count,
        ips=row.ips,
        evidence=url_to_schema(evidence) if evidence is not None else None,
        found_by=[Scanner(finding.scanner) for finding, _ in findings],
        findings=[finding_to_schema(finding, url) for finding, url in findings],
        excluded=row.excluded,
    )


def url_to_schema(row: UrlRow) -> Url:
    return Url(
        id=row.id,
        scanner=Scanner(row.scanner),
        method=row.method,
        url=row.url,
        resource_type=row.resource_type,
        status_code=row.status_code,
        failure_reason=row.failure_reason,
        auth_method=AuthMethod(row.auth_method),
        sent_auth_scheme=row.sent_auth_scheme,
        auth_challenge=row.auth_challenge,
        redirect_url=row.redirect_url,
        page_url=row.page_url,
        sources=row.sources,
    )


def job_to_schema(row: ScanJobRow) -> ScanJob:
    return ScanJob(
        scanner=Scanner(row.scanner),
        status=JobStatus(row.status),
        started_at=_isoformat(row.started_at),
        completed_at=_isoformat(row.completed_at),
        error=row.error,
        pages_crawled=row.pages_crawled,
    )


def scan_to_summary(
    scan: ScanRow,
    *,
    blocker_count: int,
    service_count: int,
    submitted_at: datetime | None = None,
    submitted_by: str | None = None,
) -> ScanSummary:
    return ScanSummary(
        id=scan.id,
        app_id=scan.app_id,
        name=scan.name,
        url=scan.url,
        status=scan.status,
        started_at=_isoformat(scan.started_at) or "",
        completed_at=_isoformat(scan.completed_at),
        started_by=scan.started_by,
        blocker_count=blocker_count,
        service_count=service_count,
        submitted_at=_isoformat(submitted_at),
        submitted_by=submitted_by,
    )


def derive_exposure_state(
    last_status: Optional[str],
    last_blocker_count: int,
    *,
    is_submitted: bool = False,
) -> ExposureState:
    # Sticky: once an app has any submission, its canonical state is "submitted",
    # regardless of what newer non-submitted scans look like. Only another submit
    # advances the canonical version.
    if is_submitted:
        return ExposureState.submitted
    if last_status is None:
        return ExposureState.never_scanned
    if last_status in ("queued", "running"):
        return ExposureState.never_scanned
    # A partial scan lacks a scanner's results, so like a failed one it can
    # only be rerun: it can be neither submitted nor edited.
    if last_status in ("failed", "cancelled", "partial"):
        return ExposureState.failed
    return (
        ExposureState.blocked
        if last_blocker_count > 0
        else ExposureState.ready_for_submission
    )


def app_to_summary(
    app: AppRow,
    *,
    last_scan: Optional[ScanRow],
    last_scan_blocker_count: int,
) -> AppSummary:
    # `current_scan_id` is set only on submit success, so its presence is the
    # authoritative signal that the app has been submitted.
    is_submitted = app.current_scan_id is not None
    return AppSummary(
        id=app.id,
        name=app.name,
        url=app.url,
        owner_ad_group=app.owner_ad_group or "",
        exposure_state=derive_exposure_state(
            last_scan.status if last_scan else None,
            last_scan_blocker_count,
            is_submitted=is_submitted,
        ),
        last_scan_id=last_scan.id if last_scan else None,
        last_scan_status=ScanStatus(last_scan.status) if last_scan else None,
        last_scanned_at=_isoformat(last_scan.started_at) if last_scan else None,
        current_scan_id=app.current_scan_id,
    )


def scan_to_detail(
    scan: ScanRow,
    *,
    blocker_count: int,
    service_count: int,
    auth_methods: int,
    jobs: Sequence[ScanJobRow],
    submitted_at: datetime | None = None,
    submitted_by: str | None = None,
) -> ScanDetail:
    duration_ms: int | None = None
    if scan.completed_at and scan.started_at:
        duration_ms = int((scan.completed_at - scan.started_at).total_seconds() * 1000)
    # Only the interceptor crawls pages; 0 until its job completes.
    pages_crawled = next(
        (job.pages_crawled or 0 for job in jobs if job.scanner == Scanner.interceptor.value), 0
    )
    return ScanDetail(
        id=scan.id,
        app_id=scan.app_id,
        name=scan.name,
        url=scan.url,
        status=scan.status,
        started_at=_isoformat(scan.started_at) or "",
        completed_at=_isoformat(scan.completed_at),
        started_by=scan.started_by,
        blocker_count=blocker_count,
        service_count=service_count,
        duration_ms=duration_ms,
        pages_crawled=pages_crawled,
        auth_methods_identified=auth_methods,
        jobs=[job_to_schema(job) for job in jobs],
        submitted_at=_isoformat(submitted_at),
        submitted_by=submitted_by,
    )
