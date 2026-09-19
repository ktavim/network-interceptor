import os
from datetime import datetime, timezone
from typing import AsyncIterator, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
    update,
)
from sqlalchemy.dialects.sqlite import JSON
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
    # submission. use_alter avoids the apps<->scans circular FK on create_all.
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

    findings: Mapped[list["FindingRow"]] = relationship(
        "FindingRow", back_populates="scan", cascade="all, delete-orphan"
    )
    submissions: Mapped[list["SubmissionRow"]] = relationship(
        "SubmissionRow", back_populates="scan", cascade="all, delete-orphan"
    )
    events: Mapped[list["ScanEventRow"]] = relationship(
        "ScanEventRow", back_populates="scan", cascade="all, delete-orphan"
    )


class FindingRow(Base):
    __tablename__ = "findings"
    __table_args__ = (
        # A finding is one origin -- the (scheme, host, port) listener -- per scan.
        # The scan diff in routes_apps keys on this triple, so it must be unique.
        UniqueConstraint("scan_id", "scheme", "host", "port", name="uq_findings_scan_origin"),
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
    first_seen_on_page: Mapped[str] = mapped_column(String, default="", nullable=False)
    headers_snippet: Mapped[str] = mapped_column(Text, default="", nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    excluded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    scan: Mapped[ScanRow] = relationship("ScanRow", back_populates="findings")


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
    __table_args__ = (
        UniqueConstraint("scan_id", "seq", name="uq_scan_events_scan_seq"),
    )

    scan_id: Mapped[str] = mapped_column(
        String, ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    seq: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[int] = mapped_column(Integer, nullable=False)
    type: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    scan: Mapped[ScanRow] = relationship("ScanRow", back_populates="events")


def _database_url() -> str:
    explicit = os.environ.get("DATABASE_URL")
    if explicit:
        return explicit
    path = os.environ.get("SCRAPER_SQLITE_PATH", "scraper.db")
    return f"sqlite+aiosqlite:///{path}"


def make_engine() -> AsyncEngine:
    engine = create_async_engine(_database_url(), future=True)
    if engine.dialect.name == "sqlite":
        @event.listens_for(engine.sync_engine, "connect")
        def _enable_sqlite_foreign_keys(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    return engine


def make_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def init_db(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def sweep_stale_scans(session_factory: async_sessionmaker[AsyncSession]) -> int:
    """Mark any scans left in queued/running by a previous process as failed."""
    async with session_factory() as session:
        stmt = (
            update(ScanRow)
            .where(ScanRow.status.in_(["queued", "running"]))
            .values(status="failed", completed_at=_utcnow(), error="server restarted")
        )
        result = await session.execute(stmt)
        await session.commit()
        return result.rowcount or 0


async def get_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    async with session_factory() as session:
        yield session
