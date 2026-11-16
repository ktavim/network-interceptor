from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.enums import (
    AuthMethod,
    ExposurePhase,
    ExposureScope,
    ExposureStatus,
    JobStatus,
    Scanner,
    ScanStatus,
    Severity,
    SourceKind,
)


class ExposureState(str, Enum):
    never_scanned = "never_scanned"
    ready_for_submission = "ready_for_submission"
    # A blocker or a review not excluded on the latest scan.
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
    # The URL of the VIP that publishes the origin, for the rewrite map of
    # every app that calls it. None on an entry added by hand until someone
    # fills it in.
    url: Optional[str] = None
    # The exposure whose deploy registered the entry; None for one added by hand.
    exposure_id: Optional[str] = None


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
    # The combined verdict itself, whatever the label was set to since: where
    # it differs from auth_method, a person set the label, and PATCHing it
    # back undoes that. None only for a service with no findings.
    scanners_auth_method: Optional[AuthMethod] = None
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
    # Services not excluded, by severity. Either one above 0 refuses submit.
    blocker_count: int
    review_count: int
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


class ExposureNotice(BaseModel):
    """A reason an exposure cannot be planned, or a warning about one of its
    services. `code` is stable for the console to key on; `message` is for
    the admin."""

    code: str
    message: str
    # The service it is about; None for one about the whole exposure.
    service_id: Optional[str] = None


class ExposureApp(BaseModel):
    id: str
    name: str
    # The app's own VIP is built from it; planning is blocked while it is None.
    url: Optional[str] = None


class ExposureSummary(BaseModel):
    """An exposure as the queue and the history list it."""

    model_config = ConfigDict(use_enum_values=True)

    id: str
    status: ExposureStatus
    # Every admin write names the version it was made against.
    version: int
    app: ExposureApp
    # The submitted scan the exposure is pinned to.
    scan_id: str
    submitted_at: str
    submitted_by: str
    created_at: str
    # The services the exposure gives a VIP.
    needs_vip_count: int
    # Whether anything blocks planning; the detail lists what.
    blocked: bool


class ExposureGroup(BaseModel):
    """A VIP group: the services that will share one VIP."""

    id: str
    service_ids: List[str]


class ExposureService(Service):
    """One of the scan's services, with what the exposure does with it,
    worked out against the published-origins registry as it is now."""

    scope: ExposureScope
    # The group of a service that needs a VIP; None until it is in one, and
    # for every other scope.
    group_id: Optional[str] = None
    # For a published service, the active registry entry that publishes it,
    # whose `url` the app's rewrite map uses. For an unresolved one, the
    # removed entry that published it on the scan.
    registry_entry: Optional[PublishedOrigin] = None
    warnings: List[ExposureNotice] = Field(default_factory=list)


class ExposureDetail(ExposureSummary):
    """An exposure as the workspace shows it."""

    groups: List[ExposureGroup]
    # Every service of the scan, in origin order, whatever its scope.
    services: List[ExposureService]
    # What blocks planning; empty when a plan can be requested.
    blocked_by: List[ExposureNotice]
    # The exposure of the app's earlier submission that this one replaced,
    # and the one of a later submission that replaced this one.
    supersedes: Optional[str] = None
    superseded_by: Optional[str] = None
    # The agent's plan, from `awaiting_confirmation` on: what the admin
    # confirms, by its hash. None before a plan, and once the grouping changes.
    plan: Optional[Dict[str, Any]] = None
    plan_hash: Optional[str] = None
    plan_version: Optional[int] = None
    confirmed_by: Optional[str] = None
    confirmed_at: Optional[str] = None
    # Set while `failed`: what failed, for the admin to retry or cancel.
    failed: Optional["ExposureFailure"] = None
    # Once deployed: the agent's references on the F5 and in DNS, and the
    # origins the deploy registered as published.
    deployment: Optional[Dict[str, Any]] = None
    deployed_at: Optional[str] = None


class ExposureFailure(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    # The phase retry resumes.
    phase: ExposurePhase
    step: Optional[str] = None
    message: Optional[str] = None


class VersionRequest(BaseModel):
    """An admin action on an exposure, made against the version they saw."""

    version: int


class ConfirmRequest(VersionRequest):
    """Approve the plan with this hash, and no other."""

    plan_hash: str


class AgentStepRequest(BaseModel):
    """One step the agent reports. `seq` is the agent's own number for it,
    unique per exposure: a repeat is recorded once."""

    seq: int = Field(ge=0)
    version: int
    step: str
    state: Literal["started", "done", "failed", "skipped", "info"]
    message: Optional[str] = None
    detail: Optional[Dict[str, Any]] = None


class AgentResultRequest(BaseModel):
    """The outcome of a phase, for a version. `plan` with a planning result
    that succeeded, `deployment` with a deploying one; `step` and `message`
    with one that failed."""

    model_config = ConfigDict(use_enum_values=False)

    version: int
    phase: ExposurePhase
    outcome: Literal["ok", "failed"]
    plan: Optional[Dict[str, Any]] = None
    # The references the deploy created: the partition, its virtual servers,
    # the DNS records, the app's public URL.
    deployment: Optional[Dict[str, Any]] = None
    step: Optional[str] = None
    message: Optional[str] = None


class AgentResultResponse(BaseModel):
    # False for a result about another version, or a status already left.
    applied: bool

def _clean_url(value: str, schemes: tuple[str, ...]) -> str:
    """A URL with one of `schemes` and a host, its scheme and host lowercased
    and any trailing slash dropped, or ValueError."""
    value = value.strip()
    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    if scheme not in schemes:
        raise ValueError(f"the URL must start with {' or '.join(s + '://' for s in schemes)}")
    if not parts.hostname:
        raise ValueError("the URL must name a host")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("the URL must not carry credentials, a query or a fragment")
    host = parts.hostname  # urlsplit lowercases it and drops IPv6 brackets
    netloc = f"[{host}]" if ":" in host else host
    if parts.port is not None:  # raises ValueError for a port out of range
        netloc += f":{parts.port}"
    return urlunsplit((scheme, netloc, parts.path.rstrip("/"), "", ""))


class PatchPublishedOriginRequest(BaseModel):
    """The URL of the VIP that publishes a registry entry's origin. HTTPS
    only: the app's own VIP serves HTTPS, and a browser blocks calls from it
    to an http:// URL as mixed content."""

    url: str

    @field_validator("url")
    @classmethod
    def _valid_url(cls, value: str) -> str:
        return _clean_url(value, ("https",))


class GroupInput(BaseModel):
    """One VIP group in a saved grouping. `id` keeps an existing group's id,
    so a client's reference to it survives the save; leave it out for a new
    group."""

    id: Optional[str] = None
    service_ids: List[str]


class SaveGroupingRequest(BaseModel):
    """The whole grouping, replacing the saved one. `version` is the version
    the admin was looking at; a save against an older one is refused."""

    version: int
    groups: List[GroupInput]

class CreateAppRequest(BaseModel):
    name: str
    # Where the app is reached: its scans start here, and its exposure's VIP
    # is built from it. Kept as given, path, query and fragment included,
    # since a scan may need to start on a particular page.
    url: str
    owner_ad_group: str

    @field_validator("url")
    @classmethod
    def _valid_url(cls, value: str) -> str:
        """http or https, a host, a valid port, no credentials: what a scan
        and the app's VIP need. Refused here rather than at deploy."""
        value = value.strip()
        parts = urlsplit(value)
        if parts.scheme.lower() not in ("http", "https"):
            raise ValueError("the URL must start with http:// or https://")
        if not parts.hostname:
            raise ValueError("the URL must name a host")
        if parts.username or parts.password:
            raise ValueError("the URL must not carry credentials")
        parts.port  # raises ValueError for a port out of range
        return value


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
