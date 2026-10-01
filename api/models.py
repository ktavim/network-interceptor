from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from core.enums import AuthMethod, JobStatus, Scanner, ScanStatus, Severity


class ExposureState(str, Enum):
    never_scanned = "never_scanned"
    ready_for_submission = "ready_for_submission"
    blocked = "blocked"
    submitted = "submitted"
    failed = "failed"


class Url(BaseModel):
    """One request behind a service: a request the browser made, captured by
    the interceptor, or a probe the tracer sent."""

    model_config = ConfigDict(use_enum_values=True)

    id: str
    # The scanner whose evidence this is.
    scanner: Scanner
    method: str
    url: str
    resource_type: str
    status_code: int
    # The browser's error text when the request got no response (status_code 0).
    failure_reason: Optional[str] = None
    auth_method: AuthMethod
    sent_auth_scheme: Optional[str] = None
    auth_challenge: Optional[str] = None
    # A redirect's target (query, fragment and userinfo stripped); None when
    # the response was not a redirect.
    redirect_url: Optional[str] = None
    page_url: str
    # Where the tracer found the URL: its provenance strings ("network:",
    # "js:", "dom:", "redirect:", "synthesized:"). Empty for the interceptor,
    # whose provenance is page_url.
    sources: List[str] = Field(default_factory=list)


class Finding(BaseModel):
    """One scanner's own verdict for a service's origin."""

    model_config = ConfigDict(use_enum_values=True)

    scanner: Scanner
    auth_method: AuthMethod
    severity: Severity
    # The request, one of this scanner's, whose classification is the verdict.
    evidence: Optional[Url] = None


class Service(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    id: str
    scheme: str
    host: str
    port: int
    # The combined verdict of the scanners' findings (core.merge), until a
    # person fills in one the scanners could not tell.
    auth_method: AuthMethod
    severity: Severity
    request_count: int
    ips: Optional[List[str]] = None
    # The request whose authentication classification won for this origin:
    # the evidence of the finding that won the merge. It is the service's
    # evidence: status, page, challenge and redirect URL. None only for a
    # service that has no such row.
    evidence: Optional[Url] = None
    # The scanners that found the origin, and each one's own verdict for it.
    found_by: List[Scanner]
    findings: List[Finding]
    excluded: bool


class ScanSummary(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    id: str
    app_id: str
    name: str
    url: str
    status: ScanStatus
    started_at: str
    completed_at: Optional[str] = None
    started_by: str
    blocker_count: int
    service_count: int
    submitted_at: Optional[str] = None
    submitted_by: Optional[str] = None


class ScanJob(BaseModel):
    """One scanner's run of a scan."""

    model_config = ConfigDict(use_enum_values=True)

    scanner: Scanner
    status: JobStatus
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None
    # None until the job completes, and for the tracer, which counts no pages.
    pages_crawled: Optional[int] = None


class ScanDetail(ScanSummary):
    duration_ms: Optional[int] = None
    # The interceptor job's; 0 until it completes.
    pages_crawled: Optional[int] = None
    auth_methods_identified: Optional[int] = None
    jobs: List[ScanJob]


class ScanEvent(BaseModel):
    scan_id: str
    seq: str
    ts: int
    type: str
    payload: dict = Field(default_factory=dict)


class ExclusionChange(BaseModel):
    id: str
    scheme: str
    host: str
    port: int
    before: bool
    after: bool


class AuthMethodChange(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    id: str
    scheme: str
    host: str
    port: int
    before: AuthMethod
    after: AuthMethod


class ScanDiff(BaseModel):
    from_scan_id: str
    to_scan_id: str
    added: List[Service]
    removed: List[Service]
    exclusion_changes: List[ExclusionChange]
    auth_method_changes: List[AuthMethodChange]


class AppSummary(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    id: str
    name: str
    url: Optional[str] = None
    owner_ad_group: str
    exposure_state: ExposureState
    last_scan_id: Optional[str] = None
    last_scan_status: Optional[ScanStatus] = None
    last_scanned_at: Optional[str] = None
    current_scan_id: Optional[str] = None


class CreateAppRequest(BaseModel):
    name: str
    url: str
    owner_ad_group: str


class CreateScanRequest(BaseModel):
    app_id: str
    max_depth: Optional[int] = Field(default=None, ge=1, le=10)


class CreateScanResponse(BaseModel):
    scan_id: str


class PatchServiceRequest(BaseModel):
    # Both fields optional so a PATCH can carry an exclusion toggle, a manual
    # auth-method correction, or both. A body with neither is a no-op.
    excluded: Optional[bool] = None
    auth_method: Optional[AuthMethod] = None


class SubmitScanResponse(BaseModel):
    submission_id: str


class CurrentUser(BaseModel):
    username: str
    display_name: str
    email: str


class ErrorResponse(BaseModel):
    message: str
