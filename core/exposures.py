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

from sqlalchemy import delete, func, select, tuple_
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
    NON_EXCLUSIVE_EXPOSURE_STATUSES,
    AuthMethod,
    ExposurePhase,
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
    services: Sequence[ServiceRow],
    found_by: Mapping[str, Iterable[str]],
    group_of: Mapping[str, str],
    registry: Mapping[Origin, PublishedOriginRow],
    scan_entries: Mapping[str, PublishedOriginRow] = {},
    deploying: Sequence[str] = (),
) -> Assessment:
    """The scope of every service of an exposure's scan, the warnings on the
    ones the rewrite map covers, and the reasons planning is blocked.

    `deploying` is the app's other exposures that are deploying.
    `found_by` maps a service id to the scanners that found it, `group_of` a
    grouped service's id to its group's, and `scan_entries` a service id to
    the registry entry its published_origin_id points at.
    """
    out = Assessment()
    for exposure_id in deploying:
        # Its origins reach the registry when it has deployed; planning before
        # then would plan them a second time.
        out.blocked_by.append(Notice(
            "earlier_exposure_deploying",
            f"{exposure_id}, an earlier submission of this app, is still deploying; plan once it has finished.",
        ))
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


def registry_for(
    registry: Mapping[Origin, PublishedOriginRow], exposure_id: str
) -> dict[Origin, PublishedOriginRow]:
    """The registry as one exposure reads it: without the entries its own
    deploy registered. Those are the services it publishes, not services
    someone else published."""
    return {origin: entry for origin, entry in registry.items() if entry.exposure_id != exposure_id}


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


async def load_deploying(session: AsyncSession, app_ids: Sequence[str]) -> dict[str, list[str]]:
    """The ids of each app's exposures that are deploying, by app id."""
    rows = await session.execute(
        select(ExposureRow.app_id, ExposureRow.id)
        .where(ExposureRow.app_id.in_(app_ids), ExposureRow.status == ExposureStatus.deploying.value)
        .order_by(ExposureRow.created_at)
    )
    out: dict[str, list[str]] = {app_id: [] for app_id in app_ids}
    for app_id, exposure_id in rows.all():
        out[app_id].append(exposure_id)
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
    *,
    agent_seq: Optional[int] = None,
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
        agent_seq=agent_seq,
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
    the default grouping of the services that need a VIP.

    The app's open exposure, if it has one in grouping, planning, awaiting
    confirmation or failed, is superseded by it. One that never asked for a
    plan holds nothing and closes at once; any other goes to `cancelling`,
    for the agent to release what it holds, and closes as superseded when the
    agent is done. An exposure that is deploying is left to finish, and one
    already cancelling to wind down. The new exposure starts from the
    grouping of the one it supersedes, or failing that of the one deploying,
    for the origins they share.
    """
    others = list(
        (
            await session.execute(
                select(ExposureRow)
                .where(
                    ExposureRow.app_id == app_id,
                    ExposureRow.status.not_in([s.value for s in CLOSED_EXPOSURE_STATUSES]),
                )
                .order_by(ExposureRow.created_at.desc())
                .with_for_update()
            )
        ).scalars()
    )
    non_exclusive = {s.value for s in NON_EXCLUSIVE_EXPOSURE_STATUSES}
    superseded = next((e for e in others if e.status not in non_exclusive), None)
    deploying = next((e for e in others if e.status == ExposureStatus.deploying.value), None)

    template = superseded or deploying
    previous = await _previous_grouping(session, template.id) if template is not None else []
    if superseded is not None:
        if superseded.status == ExposureStatus.grouping.value and superseded.first_planned_at is None:
            superseded.status = ExposureStatus.superseded.value
        else:
            superseded.status = ExposureStatus.cancelling.value
            # A plan or result in flight for the old version is dropped.
            superseded.version += 1
        # Out of the exclusive statuses before the new one is inserted.
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
        "supersedes": superseded.id if superseded is not None else None,
    })
    if superseded is not None:
        superseded.superseded_by_id = exposure.id
        if superseded.status == ExposureStatus.superseded.value:
            await emit_exposure_event(
                session, superseded.id, "exposure_superseded", submitted_by, {"by": exposure.id}
            )
        else:
            await emit_exposure_event(
                session, superseded.id, "supersede_requested", submitted_by,
                {"by": exposure.id, "version": superseded.version},
            )
    return exposure


# The statuses whose grouping an admin may change. A change in `planning` or
# `awaiting_confirmation` drops the plan: the exposure goes back to grouping.
EDITABLE_STATUSES = (
    ExposureStatus.grouping,
    ExposureStatus.planning,
    ExposureStatus.awaiting_confirmation,
)


def validate_grouping(
    groups: Sequence[Sequence[str]], services: Sequence[ServiceRow], assessment: Assessment
) -> list[Notice]:
    """What is wrong with a grouping, one notice per service: each service
    that needs a VIP must be in exactly one group, and no other may be in any.
    Empty when it can be saved."""
    by_id = {service.id: service for service in services}
    errors: dict[str, Notice] = {}
    seen: set[str] = set()
    for group in groups:
        for service_id in group:
            if service_id in errors:
                continue
            service = by_id.get(service_id)
            if service is None:
                errors[service_id] = Notice(
                    "unknown_service",
                    f"{service_id} is not a service of this exposure's scan.",
                    service_id,
                )
                continue
            origin = format_origin(origin_of(service))
            scope = assessment.services[service_id].scope
            if scope is not ExposureScope.needs_vip:
                errors[service_id] = Notice(
                    "not_in_scope", f"{origin} does not need a VIP ({scope.value}).", service_id
                )
            elif service_id in seen:
                errors[service_id] = Notice(
                    "duplicate", f"{origin} is in more than one group.", service_id
                )
            seen.add(service_id)
    for service in services:
        if (
            assessment.services[service.id].scope is ExposureScope.needs_vip
            and service.id not in seen
            and service.id not in errors
        ):
            errors[service.id] = Notice(
                "service_ungrouped",
                f"{format_origin(origin_of(service))} is not in a group.",
                service.id,
            )
    return list(errors.values())


async def save_grouping(
    session: AsyncSession,
    exposure: ExposureRow,
    groups: Sequence[tuple[Optional[str], Sequence[str]]],
    actor: str,
) -> None:
    """Replace the exposure's grouping with `groups`, each (group id or None,
    service ids), already validated. Empty groups are dropped. A group keeps
    its id when it names one of this exposure's groups, so the console's
    selection survives a save; any other gets a new one. Increments the
    version and moves the exposure to `grouping`, in the caller's
    transaction, with the event that records it."""
    existing = {
        group_id
        for group_id in (
            await session.execute(
                select(ExposureGroupRow.id).where(ExposureGroupRow.exposure_id == exposure.id)
            )
        ).scalars()
    }
    await session.execute(
        delete(ExposureGroupMemberRow).where(ExposureGroupMemberRow.exposure_id == exposure.id)
    )
    await session.execute(delete(ExposureGroupRow).where(ExposureGroupRow.exposure_id == exposure.id))

    kept: list[tuple[str, Sequence[str]]] = []
    used: set[str] = set()
    for group_id, service_ids in groups:
        if not service_ids:
            continue
        if group_id not in existing or group_id in used:
            group_id = "grp_" + uuid.uuid4().hex[:10]
        used.add(group_id)
        kept.append((group_id, service_ids))
    session.add_all(
        ExposureGroupRow(id=group_id, exposure_id=exposure.id, position=position)
        for position, (group_id, _) in enumerate(kept)
    )
    # The groups first: no relationship tells the flush that members need them.
    await session.flush()
    session.add_all(
        ExposureGroupMemberRow(exposure_id=exposure.id, service_id=service_id, group_id=group_id)
        for group_id, service_ids in kept
        for service_id in service_ids
    )

    previous = exposure.status
    exposure.version += 1
    exposure.status = ExposureStatus.grouping.value
    exposure.plan = exposure.plan_hash = exposure.plan_version = None
    payload: dict[str, Any] = {"version": exposure.version, "groups": len(kept)}
    if previous != ExposureStatus.grouping.value:
        # The plan for the old grouping is dropped; the agent's result for it,
        # naming the old version, will be ignored.
        payload["from_status"] = previous
    await emit_exposure_event(session, exposure.id, "grouping_saved", actor, payload)
    await session.flush()


async def drop_published_from_groupings(
    session: AsyncSession, origins: Sequence[Origin], *, by: str, actor: str
) -> list[str]:
    """Take the services on `origins`, which exposure `by` has just
    published, out of the groupings of the other open exposures, so that none
    gives them a second VIP. Each exposure changed loses its plan and returns
    to grouping with a new version, so a plan in flight for it is dropped,
    and records an event naming the origins. A failed exposure changes only if
    its plan failed: a failed deploy has a confirmed plan, which cancel undoes.
    Returns the ids of the exposures changed."""
    if not origins:
        return []
    statuses = [s.value for s in (*EDITABLE_STATUSES, ExposureStatus.failed)]
    rows = (
        await session.execute(
            select(ExposureRow, ExposureGroupMemberRow.service_id, ServiceRow)
            .join(ExposureGroupMemberRow, ExposureGroupMemberRow.exposure_id == ExposureRow.id)
            .join(ServiceRow, ServiceRow.id == ExposureGroupMemberRow.service_id)
            .where(
                ExposureRow.id != by,
                ExposureRow.status.in_(statuses),
                tuple_(ServiceRow.scheme, ServiceRow.host, ServiceRow.port).in_(list(origins)),
            )
            .order_by(ExposureRow.id)
            .with_for_update(of=ExposureRow)
        )
    ).all()
    affected: dict[str, tuple[ExposureRow, list[ServiceRow]]] = {}
    for exposure, _, service in rows:
        if exposure.status == ExposureStatus.failed.value and exposure.failed_phase != ExposurePhase.planning.value:
            continue
        affected.setdefault(exposure.id, (exposure, []))[1].append(service)

    for exposure, services in affected.values():
        await session.execute(
            delete(ExposureGroupMemberRow).where(
                ExposureGroupMemberRow.exposure_id == exposure.id,
                ExposureGroupMemberRow.service_id.in_([s.id for s in services]),
            )
        )
        # The groups left empty go too, as a save drops empty groups.
        await session.execute(
            delete(ExposureGroupRow).where(
                ExposureGroupRow.exposure_id == exposure.id,
                ExposureGroupRow.id.not_in(
                    select(ExposureGroupMemberRow.group_id).where(
                        ExposureGroupMemberRow.exposure_id == exposure.id
                    )
                ),
            )
        )
        previous = exposure.status
        exposure.version += 1
        exposure.status = ExposureStatus.grouping.value
        exposure.plan = exposure.plan_hash = exposure.plan_version = None
        exposure.failed_phase = exposure.failed_step = exposure.failed_message = None
        payload: dict[str, Any] = {
            "version": exposure.version,
            "by": by,
            "origins": sorted(format_origin(origin_of(s)) for s in services),
        }
        if previous != ExposureStatus.grouping.value:
            payload["from_status"] = previous
        await emit_exposure_event(session, exposure.id, "grouping_pruned", actor, payload)
    return list(affected)


async def notify_open_exposures(
    session: AsyncSession,
    event_type: str,
    actor: str,
    payload: dict[str, Any],
    *,
    app_id: Optional[str] = None,
    origin: Optional[Origin] = None,
) -> list[str]:
    """Record an event on every open exposure it concerns: the app's, or each
    one whose scan has a service on `origin`. A change outside the exposure,
    to the app or the registry, can change what blocks planning, so the
    workspaces following those exposures reload. Returns their ids."""
    stmt = select(ExposureRow.id).where(
        ExposureRow.status.not_in([s.value for s in CLOSED_EXPOSURE_STATUSES])
    )
    if app_id is not None:
        stmt = stmt.where(ExposureRow.app_id == app_id)
    if origin is not None:
        scheme, host, port = origin
        stmt = stmt.where(
            ExposureRow.scan_id.in_(
                select(ServiceRow.scan_id).where(
                    ServiceRow.scheme == scheme, ServiceRow.host == host, ServiceRow.port == port
                )
            )
        )
    ids = list((await session.execute(stmt.order_by(ExposureRow.id))).scalars())
    for exposure_id in ids:
        await emit_exposure_event(session, exposure_id, event_type, actor, payload)
    return ids
