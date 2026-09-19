"""Helpers that turn ORM rows into the shapes the frontend expects."""
from datetime import datetime, timezone
from typing import Iterable, Optional

from .db import AppRow, FindingRow, ScanRow
from .models import (
    AppSummary,
    AuthMethod,
    ExposureState,
    Finding,
    FindingEvidence,
    ScanDetail,
    ScanStatus,
    ScanSummary,
    Severity,
)


def _isoformat(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def finding_to_schema(row: FindingRow) -> Finding:
    return Finding(
        id=row.id,
        scheme=row.scheme,
        host=row.host,
        port=row.port,
        auth_method=AuthMethod(row.auth_method),
        severity=Severity(row.severity),
        request_count=row.request_count,
        first_seen_on_page=row.first_seen_on_page,
        evidence=FindingEvidence(
            headers_snippet=row.headers_snippet,
            status_code=row.status_code,
        ),
        excluded=row.excluded,
    )


def findings_to_schemas(rows: Iterable[FindingRow]) -> list[Finding]:
    return [finding_to_schema(r) for r in rows]


def scan_to_summary(
    scan: ScanRow,
    *,
    blocker_count: int,
    finding_count: int,
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
        finding_count=finding_count,
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
    if last_status in ("failed", "cancelled"):
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
    finding_count: int,
    external_services: int,
    auth_methods: int,
    submitted_at: datetime | None = None,
    submitted_by: str | None = None,
) -> ScanDetail:
    duration_ms: int | None = None
    if scan.completed_at and scan.started_at:
        duration_ms = int((scan.completed_at - scan.started_at).total_seconds() * 1000)
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
        finding_count=finding_count,
        duration_ms=duration_ms,
        pages_crawled=scan.pages_crawled,
        external_services=external_services,
        auth_methods_identified=auth_methods,
        submitted_at=_isoformat(submitted_at),
        submitted_by=submitted_by,
    )
