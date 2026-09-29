import os
from datetime import datetime, timezone
from typing import AsyncIterator, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    select,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


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
    __tablename__ = "scans"

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
    max_depth: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    pages_crawled: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # The worker that claimed the scan; for diagnostics only.
    worker_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    # Refreshed while the worker runs the scan; a stale one gets the scan reaped.
    heartbeat_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Set by the API to cancel a running scan; the worker polls it.
    cancel_requested_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
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


class ServiceRow(Base):
    """One external service a scan saw: an origin the app called, with its
    authentication classification and review state.

    Per scan, not per app: each scan records its services afresh, so the same
    service in two scans is two rows, which the scan diff matches by origin.
    """
    __tablename__ = "services"
    __table_args__ = (
        # A service is one origin -- the (scheme, host, port) listener -- per scan.
        # The scan diff in routes_apps keys on this triple, so it must be unique.
        UniqueConstraint("scan_id", "scheme", "host", "port", name="uq_services_scan_origin"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String, ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scheme: Mapped[str] = mapped_column(String, nullable=False)
    host: Mapped[str] = mapped_column(String, nullable=False)
    # Always the effective port -- 80/443 when the URL named none -- never NULL.
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    auth_method: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    request_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    # The host's DNS addresses at scan time, the F5 pool members; NULL when the lookup failed.
    ips: Mapped[Optional[list[str]]] = mapped_column(ARRAY(String), nullable=True)
    # The url row that is this service's evidence: the captured request whose
    # authentication classification won in aggregate_by_origin. The service's
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


class UrlRow(Base):
    """One captured request behind a service: per-request evidence, redacted.

    One row per capture, so a URL can repeat within a service
    (different method/status). No unique constraint and no ordering column.
    """
    __tablename__ = "urls"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    service_id: Mapped[str] = mapped_column(
        String, ForeignKey("services.id", ondelete="CASCADE"), index=True, nullable=False
    )
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


def select_services_with_evidence(scan_id: str):
    """Select (ServiceRow, UrlRow | None) pairs: a scan's services, each with
    the url row its evidence_url_id points at.

    An explicit outer join rather than a relationship: every read of a service
    wants its evidence row, and a lazy relationship load inside an async
    session raises MissingGreenlet. Callers add their own ordering.
    """
    return (
        select(ServiceRow, UrlRow)
        .outerjoin(UrlRow, UrlRow.id == ServiceRow.evidence_url_id)
        .where(ServiceRow.scan_id == scan_id)
    )


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
