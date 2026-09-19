from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ScanStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class AuthMethod(str, Enum):
    ntlm = "ntlm"
    kerberos = "kerberos"
    negotiate = "negotiate"
    oauth = "oauth"
    basic = "basic"
    bearer = "bearer"
    api_key = "api_key"
    mtls = "mtls"
    other = "other"
    unauthenticated = "unauthenticated"
    unknown = "unknown"


class Severity(str, Enum):
    blocker = "blocker"
    review = "review"
    cleared = "cleared"


class ExposureState(str, Enum):
    never_scanned = "never_scanned"
    ready_for_submission = "ready_for_submission"
    blocked = "blocked"
    submitted = "submitted"
    failed = "failed"


class FindingEvidence(BaseModel):
    headers_snippet: str = ""
    status_code: int = 0


class Finding(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    id: str
    scheme: str
    host: str
    port: int
    auth_method: AuthMethod
    severity: Severity
    request_count: int
    first_seen_on_page: str
    evidence: FindingEvidence
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
    finding_count: int
    submitted_at: Optional[str] = None
    submitted_by: Optional[str] = None


class ScanDetail(ScanSummary):
    duration_ms: Optional[int] = None
    pages_crawled: Optional[int] = None
    external_services: Optional[int] = None
    auth_methods_identified: Optional[int] = None


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
    added: List[Finding]
    removed: List[Finding]
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


class PatchFindingRequest(BaseModel):
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
