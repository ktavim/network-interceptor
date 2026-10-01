import os
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncIterator, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    select,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from .enums import AuthMethod, JobStatus, Scanner, ScanStatus, Severity


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _one_of(table: str, column: str, vocabulary: type[Enum]) -> CheckConstraint:
    """A CHECK that holds a string column to an enum's values.

    The columns stay plain strings rather than a native enum type, so a new
    value is a one-line migration (drop and re-add the constraint) instead of
    ALTER TYPE. The initial Alembic migration spells the same lists out.
    """
    values = ", ".join(f"'{member.value}'" for member in vocabulary)
    return CheckConstraint(f"{column} IN ({values})", name=f"ck_{table}_{column}")


class Base(DeclarativeBase):
    pass


class AppRow(Base):
    __tablename__ = "apps"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    url: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    owner_ad_group: Mapped[str] = mapped_column(String, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    # Canonical "current version" — the scan that was most recently submitted for
    # this app. Sticky: stays set across subsequent unsubmitted scans, only moves
    # when another scan is submitted. Nullable for apps that have never had a
    # submission. use_alter breaks the apps<->scans circular FK for table
    # ordering; the constraint itself is added explicitly in the initial
    # Alembic migration (op.create_table skips use_alter FKs on PostgreSQL).
    current_scan_id: Mapped[Optional[str]] = mapped_column(
        String,
        ForeignKey(
            "scans.id",
            ondelete="SET NULL",
            use_alter=True,
            name="fk_apps_current_scan_id",
        ),
        nullable=True,
    )


class ScanRow(Base):
    """One scan request. Its work is its jobs (ScanJobRow), one per scanner,
    and `status` is derived from theirs by core.jobs.finalize_scan."""
    __tablename__ = "scans"
    __table_args__ = (_one_of("scans", "status", ScanStatus),)

    id: Mapped[str] = mapped_column(String, primary_key=True)
    app_id: Mapped[str] = mapped_column(
        String, ForeignKey("apps.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String, nullable=False)
    url: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    started_by: Mapped[str] = mapped_column(String, nullable=False)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Set by the API to cancel the scan. On the scan, not its jobs, because a
    # cancel applies to all of them; each running job's worker polls it.
    cancel_requested_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    jobs: Mapped[list["ScanJobRow"]] = relationship(
        "ScanJobRow", back_populates="scan", cascade="all, delete-orphan"
    )
    services: Mapped[list["ServiceRow"]] = relationship(
        "ServiceRow", back_populates="scan", cascade="all, delete-orphan"
    )
    submissions: Mapped[list["SubmissionRow"]] = relationship(
        "SubmissionRow", back_populates="scan", cascade="all, delete-orphan"
    )
    events: Mapped[list["ScanEventRow"]] = relationship(
        "ScanEventRow", back_populates="scan", cascade="all, delete-orphan"
    )


class ScanJobRow(Base):
    """One scanner's run of a scan. This table is the job queue: a worker
    claims the oldest queued row for its scanner (core.jobs)."""
    __tablename__ = "scan_jobs"
    __table_args__ = (
        UniqueConstraint("scan_id", "scanner", name="uq_scan_jobs_scan_scanner"),
        # The claim query: the oldest queued job for a scanner.
        Index("ix_scan_jobs_claim", "scanner", "status", "created_at"),
        _one_of("scan_jobs", "scanner", Scanner),
        _one_of("scan_jobs", "status", JobStatus),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    scanner: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    # The scanner's settings, snapshotted when the scan was requested. Never
    # credentials: those stay in the worker's environment.
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    # How many times a worker has claimed the job.
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # The worker that claimed the job; for diagnostics only.
    worker_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    # Refreshed while the worker runs the job; a stale one gets the job reaped.
    heartbeat_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # NULL until the job completes, and for a scanner that does not count pages.
    pages_crawled: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    scan: Mapped[ScanRow] = relationship("ScanRow", back_populates="jobs")


class ServiceRow(Base):
    """One external service a scan found: an origin the app calls, with its
    authentication classification and review state.

    One row per origin, whichever scanners found it. Each scanner's own verdict
    is a ServiceFindingRow; the verdict here combines them (core.merge).

    Per scan, not per app: each scan records its services afresh, so the same
    service in two scans is two rows, which the scan diff matches by origin.
    """
    __tablename__ = "services"
    __table_args__ = (
        # A service is one origin -- the (scheme, host, port) listener -- per scan.
        # The scan diff in routes_apps keys on this triple, so it must be unique.
        # It is also the key the scanners' findings for an origin are merged on.
        UniqueConstraint("scan_id", "scheme", "host", "port", name="uq_services_scan_origin"),
        _one_of("services", "auth_method", AuthMethod),
        _one_of("services", "severity", Severity),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String, ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scheme: Mapped[str] = mapped_column(String, nullable=False)
    host: Mapped[str] = mapped_column(String, nullable=False)
    # Always the effective port -- 80/443 when the URL named none -- never NULL.
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    # The combined verdict of the scanners' findings, until a person fills in
    # one the scanners could not tell (routes_scans.patch_service).
    auth_method: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    # The service's url rows, from every scanner.
    request_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    # The host's DNS addresses at scan time, the F5 pool members: the union of
    # what the scanners resolved. NULL when no scanner resolved the host.
    ips: Mapped[Optional[list[str]]] = mapped_column(ARRAY(String), nullable=True)
    # The url row that is this service's evidence: the evidence of the finding
    # that won the merge, which is the request whose authentication
    # classification won by that scanner's own per-origin rule. The service's
    # status, page, challenge and redirect URL are all read from that row.
    # Nullable: a service can point nowhere (rows that predate the pointer).
    # services -> urls -> services is a cycle, so use_alter for table ordering
    # (as with apps.current_scan_id) and DEFERRABLE INITIALLY DEFERRED so the
    # services can be inserted ahead of the urls they point to within one
    # transaction -- both ids are minted in core.translate before either insert.
    evidence_url_id: Mapped[Optional[str]] = mapped_column(
        String,
        ForeignKey(
            "urls.id",
            ondelete="SET NULL",
            use_alter=True,
            deferrable=True,
            initially="DEFERRED",
            name="fk_services_evidence_url_id",
        ),
        index=True,
        nullable=True,
    )
    excluded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    scan: Mapped[ScanRow] = relationship("ScanRow", back_populates="services")
    # foreign_keys is explicit because evidence_url_id is a second FK path
    # between the two tables; this relationship is the urls.service_id one.
    urls: Mapped[list["UrlRow"]] = relationship(
        "UrlRow",
        back_populates="service",
        cascade="all, delete-orphan",
        foreign_keys="UrlRow.service_id",
    )
    findings: Mapped[list["ServiceFindingRow"]] = relationship(
        "ServiceFindingRow", back_populates="service", cascade="all, delete-orphan"
    )


class ServiceFindingRow(Base):
    """One scanner's own verdict for a service's origin, reached by its own
    per-origin rule. A service has one per scanner that found it."""
    __tablename__ = "service_findings"
    __table_args__ = (
        _one_of("service_findings", "scanner", Scanner),
        _one_of("service_findings", "auth_method", AuthMethod),
    )

    service_id: Mapped[str] = mapped_column(
        String, ForeignKey("services.id", ondelete="CASCADE"), primary_key=True
    )
    scanner: Mapped[str] = mapped_column(String, primary_key=True)
    auth_method: Mapped[str] = mapped_column(String, nullable=False)
    # The url row, one of this scanner's, whose classification is the verdict.
    # DEFERRABLE INITIALLY DEFERRED like services.evidence_url_id, so the
    # finding can be inserted ahead of the url it points to.
    evidence_url_id: Mapped[Optional[str]] = mapped_column(
        String,
        ForeignKey(
            "urls.id",
            ondelete="SET NULL",
            deferrable=True,
            initially="DEFERRED",
            name="fk_service_findings_evidence_url_id",
        ),
        index=True,
        nullable=True,
    )
    # This scanner's url rows for the service.
    url_count: Mapped[int] = mapped_column(Integer, nullable=False)

    service: Mapped[ServiceRow] = relationship("ServiceRow", back_populates="findings")


class UrlRow(Base):
    """One request behind a service: per-request evidence, redacted. From the
    interceptor a request the browser made, from the tracer a probe it sent.

    One row per capture, so a URL can repeat within a service
    (different method/status). No unique constraint and no ordering column.
    """
    __tablename__ = "urls"
    __table_args__ = (
        _one_of("urls", "scanner", Scanner),
        _one_of("urls", "auth_method", AuthMethod),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True)
    service_id: Mapped[str] = mapped_column(
        String, ForeignKey("services.id", ondelete="CASCADE"), index=True, nullable=False
    )
    # The scanner whose evidence this row is.
    scanner: Mapped[str] = mapped_column(String, nullable=False)
    method: Mapped[str] = mapped_column(String, nullable=False)
    # Query string, fragment and userinfo stripped.
    url: Mapped[str] = mapped_column(String, nullable=False)
    resource_type: Mapped[str] = mapped_column(String, default="", nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Why the request got no response, as the browser reported it
    # ("net::ERR_NAME_NOT_RESOLVED", "net::ERR_ABORTED"); status_code is 0 then.
    # NULL for a request that got a response.
    failure_reason: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    # Always an AuthMethod value (tag_to_auth_method), like services.auth_method.
    auth_method: Mapped[str] = mapped_column(String, nullable=False)
    # The auth-scheme word of the Authorization header the client sent
    # ("Basic", "Digest", "Negotiate"), case as sent; NULL when none was. Only
    # the scheme token is ever kept (auth_analyzer.sent_auth_scheme), never the
    # credentials after it. With auth_challenge this records both sides of the
    # exchange: what the client sent and what the server demanded.
    sent_auth_scheme: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    auth_challenge: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # A 3xx's Location, resolved against url and stripped like it; NULL for
    # any other response. Kept for every redirect, not just IdP handoffs
    # (those are the rows whose auth_method is "oauth").
    redirect_url: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    page_url: Mapped[str] = mapped_column(String, default="", nullable=False)
    # Where the tracer found the URL: its provenance strings ("network:",
    # "js:", "dom:", "redirect:", "synthesized:"). Empty for the interceptor,
    # whose provenance is page_url.
    sources: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'"), nullable=False
    )

    service: Mapped[ServiceRow] = relationship(
        "ServiceRow", back_populates="urls", foreign_keys=[service_id]
    )


class SubmissionRow(Base):
    __tablename__ = "submissions"
    __table_args__ = (
        # A scan can be submitted at most once. The `already_submitted` check in
        # routes_scans.submit_scan is single-transaction; the unique constraint
        # is what actually wins under concurrent submits — the loser hits an
        # IntegrityError and we translate it to a 409.
        UniqueConstraint("scan_id", name="uq_submissions_scan_id"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String, ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    submitted_by: Mapped[str] = mapped_column(String, nullable=False)

    scan: Mapped[ScanRow] = relationship("ScanRow", back_populates="submissions")


class ScanEventRow(Base):
    __tablename__ = "scan_events"

    scan_id: Mapped[str] = mapped_column(
        String, ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    seq: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[int] = mapped_column(BigInteger, nullable=False)
    type: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    scan: Mapped[ScanRow] = relationship("ScanRow", back_populates="events")


async def load_services(
    session: AsyncSession, scan_id: str, *, service_id: Optional[str] = None
) -> list[tuple[ServiceRow, Optional[UrlRow], list[tuple[ServiceFindingRow, Optional[UrlRow]]]]]:
    """A scan's services in origin order, or only the one with `service_id`.

    Each comes as (service, evidence, findings): the url row the service's
    evidence_url_id points at, or None, and each scanner's finding for it,
    ordered by scanner and paired the same way with its own evidence row.

    Explicit outer joins rather than relationships: every read of a service
    wants these rows, and a lazy relationship load inside an async session
    raises MissingGreenlet.
    """
    services = (
        select(ServiceRow, UrlRow)
        .outerjoin(UrlRow, UrlRow.id == ServiceRow.evidence_url_id)
        .where(ServiceRow.scan_id == scan_id)
        .order_by(ServiceRow.host, ServiceRow.port, ServiceRow.scheme)
    )
    findings = (
        select(ServiceFindingRow, UrlRow)
        .join(ServiceRow, ServiceRow.id == ServiceFindingRow.service_id)
        .outerjoin(UrlRow, UrlRow.id == ServiceFindingRow.evidence_url_id)
        .where(ServiceRow.scan_id == scan_id)
        .order_by(ServiceFindingRow.scanner)
    )
    if service_id is not None:
        services = services.where(ServiceRow.id == service_id)
        findings = findings.where(ServiceRow.id == service_id)
    by_service: dict[str, list[tuple[ServiceFindingRow, Optional[UrlRow]]]] = {}
    for finding, evidence in (await session.execute(findings)).all():
        by_service.setdefault(finding.service_id, []).append((finding, evidence))
    return [
        (service, evidence, by_service.get(service.id, []))
        for service, evidence in (await session.execute(services)).all()
    ]


def _database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "DATABASE_URL is required "
            "(example: postgresql+asyncpg://user:pass@host:5432/dbname)"
        )
    return url


def make_engine() -> AsyncEngine:
    # pool_pre_ping: pooled connections go stale when Postgres restarts or an
    # idle timeout closes them; without it the next request fails.
    return create_async_engine(_database_url(), future=True, pool_pre_ping=True)


def make_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    async with session_factory() as session:
        yield session
