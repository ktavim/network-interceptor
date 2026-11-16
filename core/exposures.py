"""Exposures: publishing a submitted app through the F5 (docs/exposure-design.md).

What an exposure covers is worked out here, every time it is read, from its
scan's services and the published-origins registry as it stands now, so the
console and the plan never disagree about what is in scope or what blocks
planning. Creating an exposure for a submission, and superseding the app's
open one, happen in the submit transaction (create_for_submission).
"""
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Mapping, Optional, Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .db import (
    ExposureEventRow,
    ExposureGroupMemberRow,
    ExposureGroupRow,
    ExposureRow,
    PublishedOriginRow,
    ServiceFindingRow,
    ServiceRow,
)
from .enums import (
    CLOSED_EXPOSURE_STATUSES,
    AuthMethod,
    ExposureScope,
    ExposureStatus,
    Scanner,
    Severity,
)
from .translate import severity_for

# (scheme, host, port): how the services table and the registry key an origin.
Origin = tuple[str, str, int]

_DEFAULT_PORTS = {"http": 80, "https": 443}

# The NOTIFY channel that wakes exposure event streams (api.sse.EventBus).
EVENT_CHANNEL = "exposure_events"
# The events that close an exposure: its stream ends after sending one.
TERMINAL_EVENTS = ("exposure_superseded", "exposure_cancelled", "exposure_deployed")


def origin_of(row: ServiceRow | PublishedOriginRow) -> Origin:
    return (row.scheme, row.host, row.port)


def format_origin(origin: Origin) -> str:
    scheme, host, port = origin
    host = f"[{host}]" if ":" in host else host
    return f"{scheme}://{host}" if _DEFAULT_PORTS.get(scheme) == port else f"{scheme}://{host}:{port}"


@dataclass(frozen=True)
class Notice:
    """A reason planning is blocked, or a warning about a service. `code` is
    for the console to key on; `message` is for the admin to read."""

    code: str
    message: str
    service_id: Optional[str] = None


@dataclass(frozen=True)
class ServiceScope:
    scope: ExposureScope
    # For a published service, the active registry entry that publishes it;
    # for an unresolved one, the removed entry that published it on the scan.
    registry_entry: Optional[PublishedOriginRow] = None
    warnings: tuple[Notice, ...] = ()


@dataclass
class Assessment:
    """An exposure's services as it stands: what it does with each, and what
    keeps it from being planned."""

    services: dict[str, ServiceScope] = field(default_factory=dict)
    blocked_by: list[Notice] = field(default_factory=list)

    @property
    def needs_vip_count(self) -> int:
        return sum(1 for s in self.services.values() if s.scope is ExposureScope.needs_vip)


def scope_of(
    service: ServiceRow,
    registry: Mapping[Origin, PublishedOriginRow],
    scan_entry: Optional[PublishedOriginRow] = None,
) -> ServiceScope:
    """What an exposure does with `service`, against the registry's active
    entries as they are now, not as they were when the scan was finished.

    An origin registered since the scan is published, as a plan would read
    it. One whose entry was removed since loses its published verdict and
    falls back on its own auth method's: a VIP if that clears, otherwise
    unresolved, since a submitted scan never vouched for it. `scan_entry` is
    the entry the service's published_origin_id points at.
    """
    if service.excluded:
        return ServiceScope(ExposureScope.excluded)
    entry = registry.get(origin_of(service))
    if entry is not None:
        return ServiceScope(ExposureScope.published, entry)
    severity = Severity(service.severity)
    if severity is Severity.published:
        severity = severity_for(AuthMethod(service.auth_method))
    if severity is Severity.cleared:
        return ServiceScope(ExposureScope.needs_vip)
    return ServiceScope(ExposureScope.unresolved, scan_entry)


def _warnings(service: ServiceRow, found_by: Iterable[str]) -> tuple[Notice, ...]:
    """The rewriting limits that apply to a service the app's rewrite map
    covers (exposure-design.md, Console: Warnings)."""
    out = []
    if Scanner.tracer.value not in found_by:
        out.append(Notice(
            "interceptor_only",
            "Found only by the interceptor: the app may assemble this origin at runtime, "
            "where the F5 cannot rewrite it.",
            service.id,
        ))
    if service.auth_method == AuthMethod.login_redirect.value:
        out.append(Notice(
            "login_redirect",
            "Login redirect: its identity provider must accept a redirect URI on the app's new name.",
            service.id,
        ))
    return tuple(out)


def assess(
    *,
    app_url: Optional[str],
    services: Sequence[ServiceRow],
    found_by: Mapping[str, Iterable[str]],
    group_of: Mapping[str, str],
    registry: Mapping[Origin, PublishedOriginRow],
    scan_entries: Mapping[str, PublishedOriginRow] = {},
) -> Assessment:
    """The scope of every service of an exposure's scan, the warnings on the
    ones the rewrite map covers, and the reasons planning is blocked.

    `found_by` maps a service id to the scanners that found it, `group_of` a
    grouped service's id to its group's, and `scan_entries` a service id to
    the registry entry its published_origin_id points at.
    """
    out = Assessment()
    if not app_url:
        out.blocked_by.append(Notice("app_url_missing", "The app has no URL; set one to plan its VIP."))
    for service in services:
        scope = scope_of(service, registry, scan_entries.get(service.id))
        if scope.scope in (ExposureScope.needs_vip, ExposureScope.published):
            scope = ServiceScope(
                scope.scope, scope.registry_entry, _warnings(service, found_by.get(service.id, ()))
            )
        out.services[service.id] = scope

        origin = format_origin(origin_of(service))
        if scope.scope is ExposureScope.needs_vip:
            if service.id not in group_of:
                out.blocked_by.append(Notice(
                    "service_ungrouped", f"{origin} is not in a VIP group.", service.id
                ))
            if service.auth_method == AuthMethod.kerberos.value:
                out.blocked_by.append(Notice(
                    "kerberos_unsupported",
                    f"{origin} uses Kerberos, which cannot be published yet; exclude it on a "
                    "new scan, or wait for Kerberos support.",
                    service.id,
                ))
        elif scope.scope is ExposureScope.published:
            if not scope.registry_entry.url:
                out.blocked_by.append(Notice(
                    "published_url_missing",
                    f"{origin} is published, but its registry entry has no URL for the "
                    "app's rewrite map.",
                    service.id,
                ))
        elif scope.scope is ExposureScope.unresolved:
            out.blocked_by.append(Notice(
                "published_origin_removed",
                f"{origin} was published when scanned, but its registry entry has since been "
                f"removed and {service.auth_method} does not clear; register it again, or "
                "rescan and resubmit the app.",
                service.id,
            ))
    return out


def propose_grouping(
    services: Sequence[ServiceRow], previous: Sequence[Sequence[Origin]] = ()
) -> list[list[str]]:
    """Groups of service ids for the services that need a VIP, in order.

    `previous` is the grouping of the exposure this one supersedes, by origin:
    its groups are kept, in order, for the origins the two share. Every other
    service joins the first group holding a service on its host, or starts a
    group of its own: one VIP per host, the default proposal.
    """
    by_origin = {origin_of(service): service for service in services}
    groups: list[list[str]] = []
    placed: set[str] = set()
    group_of_host: dict[str, int] = {}
    for old in previous:
        group = [by_origin[o] for o in old if o in by_origin and by_origin[o].id not in placed]
        if group:
            for service in group:
                group_of_host.setdefault(service.host, len(groups))
            groups.append([service.id for service in group])
            placed.update(groups[-1])
    for service in services:
        if service.id in placed:
            continue
        index = group_of_host.get(service.host)
        if index is None:
            index = group_of_host[service.host] = len(groups)
            groups.append([])
        groups[index].append(service.id)
    return groups


async def load_registry(session: AsyncSession) -> dict[Origin, PublishedOriginRow]:
    """The registry's active entries, by origin."""
    rows = await session.execute(
        select(PublishedOriginRow).where(PublishedOriginRow.removed_at.is_(None))
    )
    return {origin_of(row): row for row in rows.scalars()}


async def load_scan_services(
    session: AsyncSession, scan_ids: Sequence[str]
) -> dict[str, list[ServiceRow]]:
    """The scans' service rows by scan id, each scan's in origin order."""
    rows = await session.execute(
        select(ServiceRow)
        .where(ServiceRow.scan_id.in_(scan_ids))
        .order_by(ServiceRow.host, ServiceRow.port, ServiceRow.scheme)
    )
    out: dict[str, list[ServiceRow]] = {scan_id: [] for scan_id in scan_ids}
    for row in rows.scalars():
        out[row.scan_id].append(row)
    return out


async def load_found_by(session: AsyncSession, scan_ids: Sequence[str]) -> dict[str, list[str]]:
    """The scanners that found each service of the scans, by service id."""
    rows = await session.execute(
        select(ServiceFindingRow.service_id, ServiceFindingRow.scanner)
        .join(ServiceRow, ServiceRow.id == ServiceFindingRow.service_id)
        .where(ServiceRow.scan_id.in_(scan_ids))
        .order_by(ServiceFindingRow.scanner)
    )
    out: dict[str, list[str]] = {}
    for service_id, scanner in rows.all():
        out.setdefault(service_id, []).append(scanner)
    return out


async def load_group_members(
    session: AsyncSession, exposure_ids: Sequence[str]
) -> dict[str, dict[str, str]]:
    """Each exposure's grouped services, as {service id: group id}, by exposure id."""
    rows = await session.execute(
        select(ExposureGroupMemberRow).where(ExposureGroupMemberRow.exposure_id.in_(exposure_ids))
    )
    out: dict[str, dict[str, str]] = {exposure_id: {} for exposure_id in exposure_ids}
    for row in rows.scalars():
        out[row.exposure_id][row.service_id] = row.group_id
    return out


async def load_groups(session: AsyncSession, exposure_id: str) -> list[ExposureGroupRow]:
    rows = await session.execute(
        select(ExposureGroupRow)
        .where(ExposureGroupRow.exposure_id == exposure_id)
        .order_by(ExposureGroupRow.position)
    )
    return list(rows.scalars())


async def emit_exposure_event(
    session: AsyncSession,
    exposure_id: str,
    event_type: str,
    actor: str,
    payload: Optional[dict[str, Any]] = None,
) -> ExposureEventRow:
    """Add an event to the caller's transaction, with the next seq."""
    # As core.events.emit_event: held to commit, so max() sees every seq
    # committed before it.
    await session.execute(
        select(func.pg_advisory_xact_lock(func.hashtext(f"exposure:{exposure_id}")))
    )
    current = (
        await session.execute(
            select(func.coalesce(func.max(ExposureEventRow.seq), -1)).where(
                ExposureEventRow.exposure_id == exposure_id
            )
        )
    ).scalar_one()
    row = ExposureEventRow(
        exposure_id=exposure_id,
        seq=int(current) + 1,
        ts=int(time.time() * 1000),
        type=event_type,
        actor=actor,
        payload=payload or {},
    )
    session.add(row)
    await session.flush()
    # Ids only, as for scan events: a payload can exceed NOTIFY's 8000 bytes.
    await session.execute(
        select(func.pg_notify(EVENT_CHANNEL, f"{exposure_id}:{row.seq}:{event_type}"))
    )
    return row


def event_to_dict(row: ExposureEventRow) -> dict[str, Any]:
    return {
        "exposure_id": row.exposure_id,
        "seq": str(row.seq),
        "ts": row.ts,
        "type": row.type,
        "actor": row.actor,
        "payload": row.payload,
    }


async def replay_events(session: AsyncSession, exposure_id: str, start_seq: int) -> list[ExposureEventRow]:
    """The exposure's events from `start_seq` on, in order."""
    rows = await session.execute(
        select(ExposureEventRow)
        .where(ExposureEventRow.exposure_id == exposure_id, ExposureEventRow.seq >= start_seq)
        .order_by(ExposureEventRow.seq)
    )
    return list(rows.scalars())


async def _add_grouping(
    session: AsyncSession, exposure_id: str, groups: Sequence[Sequence[str]]
) -> None:
    group_ids = ["grp_" + uuid.uuid4().hex[:10] for _ in groups]
    session.add_all(
        ExposureGroupRow(id=group_id, exposure_id=exposure_id, position=position)
        for position, group_id in enumerate(group_ids)
    )
    # The groups first: no relationship tells the flush that members need them.
    await session.flush()
    session.add_all(
        ExposureGroupMemberRow(exposure_id=exposure_id, service_id=service_id, group_id=group_id)
        for group_id, service_ids in zip(group_ids, groups)
        for service_id in service_ids
    )


async def _previous_grouping(session: AsyncSession, exposure_id: str) -> list[list[Origin]]:
    """An exposure's grouping by origin, its groups in order."""
    rows = await session.execute(
        select(ExposureGroupMemberRow.group_id, ServiceRow.scheme, ServiceRow.host, ServiceRow.port)
        .join(ServiceRow, ServiceRow.id == ExposureGroupMemberRow.service_id)
        .join(ExposureGroupRow, ExposureGroupRow.id == ExposureGroupMemberRow.group_id)
        .where(ExposureGroupMemberRow.exposure_id == exposure_id)
        .order_by(ExposureGroupRow.position, ServiceRow.host, ServiceRow.port, ServiceRow.scheme)
    )
    groups: dict[str, list[Origin]] = {}
    for group_id, scheme, host, port in rows.all():
        groups.setdefault(group_id, []).append((scheme, host, port))
    return list(groups.values())


async def create_for_submission(
    session: AsyncSession, *, app_id: str, scan_id: str, submitted_by: str, now: datetime
) -> ExposureRow:
    """The exposure of a submission, added to the submit's transaction, with
    the default grouping of the services that need a VIP. An exposure the app
    still has open is superseded by it, and its grouping carried over for the
    origins the two share.
    """
    open_exposure = (
        await session.execute(
            select(ExposureRow)
            .where(
                ExposureRow.app_id == app_id,
                ExposureRow.status.not_in([s.value for s in CLOSED_EXPOSURE_STATUSES]),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()

    previous: list[list[Origin]] = []
    if open_exposure is not None:
        if (
            open_exposure.status != ExposureStatus.grouping.value
            or open_exposure.first_planned_at is not None
        ):
            # Unreachable until plans exist: such an exposure holds IP
            # reservations and certificates, and superseding it goes through
            # `cancelling`, with the agent releasing what the new one does not
            # take over (exposure-design.md, Lifecycle).
            raise NotImplementedError(
                f"superseding a {open_exposure.status} exposure that was planned is not built yet"
            )
        previous = await _previous_grouping(session, open_exposure.id)
        # Closed before the new one is inserted: an app has one open exposure.
        open_exposure.status = ExposureStatus.superseded.value
        await session.flush()

    registry = await load_registry(session)
    services = (await load_scan_services(session, [scan_id]))[scan_id]
    needs_vip = [s for s in services if scope_of(s, registry).scope is ExposureScope.needs_vip]

    exposure = ExposureRow(
        id="exp_" + uuid.uuid4().hex[:10],
        app_id=app_id,
        scan_id=scan_id,
        status=ExposureStatus.grouping.value,
        version=1,
        created_at=now,
    )
    session.add(exposure)
    await session.flush()
    await _add_grouping(session, exposure.id, propose_grouping(needs_vip, previous))
    await emit_exposure_event(session, exposure.id, "exposure_created", submitted_by, {
        "scan_id": scan_id,
        "supersedes": open_exposure.id if open_exposure is not None else None,
    })
    if open_exposure is not None:
        open_exposure.superseded_by_id = exposure.id
        await emit_exposure_event(
            session, open_exposure.id, "exposure_superseded", submitted_by, {"by": exposure.id}
        )
    return exposure
