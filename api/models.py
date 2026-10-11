from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.enums import AuthMethod, JobStatus, Scanner, ScanStatus, Severity, SourceKind


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


class Source(BaseModel):
    """One place a scanner found a service's origin: a tracer provenance
    string (Url.sources) split into its kind and what it names, or a page the
    interceptor's browser called the origin from (Url.page_url)."""

    model_config = ConfigDict(use_enum_values=True)

    kind: SourceKind
    # The URL of the config, bundle, probed URL or page; for dom, the page
    # element, in prose.
    value: str


class Finding(BaseModel):
    """One scanner's own verdict for a service's origin."""

    model_config = ConfigDict(use_enum_values=True)

    scanner: Scanner
    auth_method: AuthMethod
    severity: Severity
    # The request, one of this scanner's, whose classification is the verdict.
    evidence: Optional[Url] = None


class PublishedOrigin(BaseModel):
    """An entry of the published-origins registry: an origin already
    published through the F5, by a workaround the scanners cannot see. A
    service on it is `published`, whatever its auth method, on every scan
    whose verdicts are computed while the entry is active."""

    id: str
    scheme: str
    host: str
    port: int
    note: str
    added_by: str
    added_at: str
    # Set once the entry is removed. A service on a submitted scan keeps the
    # entry that published it, so a reader can see it was since removed.
    removed_at: Optional[str] = None
    removed_by: Optional[str] = None


class Service(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    id: str
    scheme: str
    host: str
    port: int
    # The combined verdict of the scanners' findings (core.merge), until a
    # person fills in one the scanners could not tell. The severity is the
    # method's, or `published` from the registry whatever the method.
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
    # Everywhere the scanners found the origin, folded over the service's urls
    # (serialize.sources_to_schema): one entry per distinct source, sorted by
    # kind then value.
    sources: List[Source]
    excluded: bool
    # The registry entry that made the service published; None under every
    # other severity. Carries `removed_at` when the entry was removed after
    # the scan.
    published_origin: Optional[PublishedOrigin] = None


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


class PublishedChange(BaseModel):
    """A service that became, or stopped being, published between two scans."""

    id: str
    scheme: str
    host: str
    port: int
    before: bool
    after: bool


class ScanDiff(BaseModel):
    from_scan_id: str
    to_scan_id: str
    added: List[Service]
    removed: List[Service]
    exclusion_changes: List[ExclusionChange]
    auth_method_changes: List[AuthMethodChange]
    published_changes: List[PublishedChange]


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


_ORIGIN_SCHEMES = ("http", "https")


class CreatePublishedOriginRequest(BaseModel):
    """An origin as the services table keys it. The scanners store
    urlparse().hostname, lowercase and without IPv6 brackets, and the
    effective port, so the input is normalized the same way."""

    scheme: str
    host: str
    port: int = Field(ge=1, le=65535)
    note: str = ""

    @field_validator("scheme")
    @classmethod
    def _normalize_scheme(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in _ORIGIN_SCHEMES:
            raise ValueError("scheme must be http or https")
        return value

    @field_validator("host")
    @classmethod
    def _normalize_host(cls, value: str) -> str:
        value = value.strip().lower()
        if value.startswith("[") and value.endswith("]"):
            value = value[1:-1]
        if not value:
            raise ValueError("host must not be empty")
        return value


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
