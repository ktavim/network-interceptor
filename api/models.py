from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from core.enums import AuthMethod, Severity


class ScanStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class ExposureState(str, Enum):
    never_scanned = "never_scanned"
    ready_for_submission = "ready_for_submission"
    blocked = "blocked"
    submitted = "submitted"
    failed = "failed"


class Url(BaseModel):
    """One captured request behind a service."""

    model_config = ConfigDict(use_enum_values=True)

    id: str
    method: str
    url: str
    resource_type: str
    status_code: int
    auth_method: AuthMethod
    sent_auth_scheme: Optional[str] = None
    auth_challenge: Optional[str] = None
    idp_redirect: Optional[str] = None
    page_url: str


class Service(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    id: str
    scheme: str
    host: str
    port: int
    auth_method: AuthMethod
    severity: Severity
    request_count: int
    ips: Optional[List[str]] = None
    # The captured request whose authentication classification won for this
    # origin. It is the service's evidence: status, page, challenge and IdP
    # redirect. None only for a service that has no such row.
    evidence: Optional[Url] = None
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


class ScanDetail(ScanSummary):
    duration_ms: Optional[int] = None
    pages_crawled: Optional[int] = None
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
