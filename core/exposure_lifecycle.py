"""An exposure's status changes (docs/exposure-design.md, Lifecycle), and the
protocol the deployment agent pulls its work through (Backend and agent
protocol).

The admin's changes are each one function: check the status and version,
change the status, and record the event that says so, in the caller's
transaction. The agent never receives anything: it asks for the exposures
waiting on it, reports steps as it goes, and reports a result that names the
version it was for. A result for any other version, or one that arrives after
the status moved on, is dropped.
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from . import exposures
from .db import AppRow, ExposureEventRow, ExposureGroupMemberRow, ExposureRow, PublishedOriginRow, ServiceRow
from .enums import ExposurePhase, ExposureScope, ExposureStatus

AGENT = "agent"

# What the agent works on, by status: each is also the phase of its result.
AGENT_STATUSES = tuple(ExposureStatus(phase.value) for phase in ExposurePhase)

# Where an admin may cancel. Cancelling while deploying is refused: a deploy
# cannot be stopped.
CANCELLABLE_STATUSES = (
    ExposureStatus.grouping,
    ExposureStatus.planning,
    ExposureStatus.awaiting_confirmation,
    ExposureStatus.failed,
)


class Refused(Exception):
    """A request the exposure's status, version or state does not allow:
    409 with the current status and version, or 422 with `extra`."""

    def __init__(self, exposure: ExposureRow, message: str, *, status_code: int = 409, **extra: Any):
        super().__init__(message)
        self.status_code = status_code
        self.detail = {"message": message, "status": exposure.status, "version": exposure.version, **extra}


def plan_hash(plan: dict[str, Any]) -> str:
    """sha256 of the plan's canonical JSON: what the admin confirms."""
    canonical = json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def assess_exposure(session: AsyncSession, exposure: ExposureRow) -> exposures.Assessment:
    """The exposure's scope and what blocks planning, as it stands now."""
    services = (await exposures.load_scan_services(session, [exposure.scan_id]))[exposure.scan_id]
    group_of = (await exposures.load_group_members(session, [exposure.id]))[exposure.id]
    deploying = (await exposures.load_deploying(session, [exposure.app_id]))[exposure.app_id]
    return exposures.assess(
        services=services,
        found_by={},
        group_of=group_of,
        registry=exposures.registry_for(await exposures.load_registry(session), exposure.id),
        deploying=[e for e in deploying if e != exposure.id],
    )


def _check(exposure: ExposureRow, version: int, allowed: tuple[ExposureStatus, ...], action: str) -> None:
    if exposure.status not in [s.value for s in allowed]:
        raise Refused(exposure, f"a {exposure.status} exposure cannot be {action}")
    if version != exposure.version:
        raise Refused(
            exposure,
            f"the exposure is at version {exposure.version}; this was asked of version {version}",
        )


def _blocked(exposure: ExposureRow, assessment: exposures.Assessment, action: str) -> None:
    if assessment.blocked_by:
        raise Refused(
            exposure,
            f"the exposure cannot be {action} while something blocks planning",
            blocked_by=[
                {"code": n.code, "message": n.message, "service_id": n.service_id}
                for n in assessment.blocked_by
            ],
        )


async def request_plan(session: AsyncSession, exposure: ExposureRow, version: int, actor: str) -> None:
    """`grouping` to `planning`: the agent reserves IPs, requests certificates,
    renders AS3 and dry-runs it."""
    _check(exposure, version, (ExposureStatus.grouping,), "planned")
    _blocked(exposure, await assess_exposure(session, exposure), "planned")
    exposure.status = ExposureStatus.planning.value
    exposure.first_planned_at = exposure.first_planned_at or datetime.now(timezone.utc)
    exposure.plan = exposure.plan_hash = exposure.plan_version = None
    await exposures.emit_exposure_event(session, exposure.id, "plan_requested", actor, {"version": version})


async def confirm(
    session: AsyncSession, exposure: ExposureRow, version: int, confirmed_hash: str, actor: str
) -> None:
    """`awaiting_confirmation` to `deploying`: an admin approves that exact
    plan. Refused if the hash is not the plan's, or if something blocks
    planning now, say a registry entry removed since the plan."""
    _check(exposure, version, (ExposureStatus.awaiting_confirmation,), "confirmed")
    if confirmed_hash != exposure.plan_hash:
        raise Refused(exposure, "that is not the exposure's current plan", plan_hash=exposure.plan_hash)
    _blocked(exposure, await assess_exposure(session, exposure), "confirmed")
    exposure.status = ExposureStatus.deploying.value
    exposure.confirmed_by = actor
    exposure.confirmed_at = datetime.now(timezone.utc)
    await exposures.emit_exposure_event(
        session, exposure.id, "plan_confirmed", actor, {"version": version, "plan_hash": confirmed_hash}
    )


async def cancel(session: AsyncSession, exposure: ExposureRow, version: int, actor: str) -> None:
    """To `cancelled` at once if the exposure never asked for a plan, so holds
    nothing; otherwise to `cancelling`, for the agent to release what it holds
    and, after a failed deploy, to undo the steps it completed, in reverse.
    Increments the version, so a plan in flight is dropped."""
    _check(exposure, version, CANCELLABLE_STATUSES, "cancelled")
    exposure.version += 1
    exposure.failed_phase = exposure.failed_step = exposure.failed_message = None
    if exposure.status == ExposureStatus.grouping.value and exposure.first_planned_at is None:
        exposure.status = ExposureStatus.cancelled.value
        await exposures.emit_exposure_event(session, exposure.id, "exposure_cancelled", actor, {})
    else:
        exposure.status = ExposureStatus.cancelling.value
        await exposures.emit_exposure_event(
            session, exposure.id, "cancel_requested", actor, {"version": exposure.version}
        )


async def retry(session: AsyncSession, exposure: ExposureRow, version: int, actor: str) -> None:
    """`failed` back to the phase that failed. The agent resumes from the step
    it last completed, from its own step log."""
    _check(exposure, version, (ExposureStatus.failed,), "retried")
    phase = exposure.failed_phase
    exposure.status = phase
    exposure.failed_phase = exposure.failed_step = exposure.failed_message = None
    await exposures.emit_exposure_event(session, exposure.id, "retry_requested", actor, {"phase": phase})


# ---- The agent's side ---------------------------------------------------------


async def pending(session: AsyncSession) -> list[dict[str, Any]]:
    """The exposures waiting on the agent, oldest first, each with what it
    needs for its status. Data only: the agent renders AS3 from its own template."""
    rows = list(
        (
            await session.execute(
                select(ExposureRow)
                .where(ExposureRow.status.in_([s.value for s in AGENT_STATUSES]))
                .order_by(ExposureRow.created_at)
            )
        ).scalars()
    )
    out = []
    for exposure in rows:
        item: dict[str, Any] = {"id": exposure.id, "status": exposure.status, "version": exposure.version}
        if exposure.status == ExposureStatus.planning.value:
            item["planning"] = await _planning_payload(session, exposure)
        elif exposure.status == ExposureStatus.deploying.value:
            # The hash only: the agent deploys its own copy of the plan it
            # made, never a declaration the backend sends.
            item["deploying"] = {"plan_hash": exposure.plan_hash}
        else:
            item["cancelling"] = {"superseded_by": exposure.superseded_by_id}
        out.append(item)
    return out


async def _planning_payload(session: AsyncSession, exposure: ExposureRow) -> dict[str, Any]:
    """The app and its URL, the VIP groups with each service's origin, auth
    method and pool members, and the registry URLs of the published services
    the app calls."""
    app = await session.get(AppRow, exposure.app_id)
    services = (await exposures.load_scan_services(session, [exposure.scan_id]))[exposure.scan_id]
    by_id = {s.id: s for s in services}
    registry = exposures.registry_for(await exposures.load_registry(session), exposure.id)
    members = (
        await session.execute(
            select(ExposureGroupMemberRow).where(ExposureGroupMemberRow.exposure_id == exposure.id)
        )
    ).scalars()
    in_group: dict[str, list[ServiceRow]] = {}
    for member in members:
        service = by_id[member.service_id]
        # A grouped service published since by another exposure is not
        # planned twice; the next save drops it from the grouping.
        if exposures.scope_of(service, registry).scope is ExposureScope.needs_vip:
            in_group.setdefault(member.group_id, []).append(service)
    groups = []
    for group in await exposures.load_groups(session, exposure.id):
        grouped = sorted(in_group.get(group.id, []), key=lambda s: (s.host, s.port, s.scheme))
        if not grouped:
            continue
        groups.append({
            "id": group.id,
            "services": [
                {
                    "id": s.id,
                    "scheme": s.scheme,
                    "host": s.host,
                    "port": s.port,
                    "auth_method": s.auth_method,
                    "ips": s.ips or [],
                }
                for s in grouped
            ],
        })
    published = []
    for service in services:
        scope = exposures.scope_of(service, registry)
        if scope.scope is ExposureScope.published:
            published.append({
                "scheme": service.scheme,
                "host": service.host,
                "port": service.port,
                "url": scope.registry_entry.url,
            })
    return {
        "app": {"id": app.id, "name": app.name, "url": app.url},
        "groups": groups,
        "published": published,
    }


async def record_agent_step(
    session: AsyncSession, exposure: ExposureRow, *, seq: int, version: int, step: str, state: str,
    message: Optional[str], detail: Optional[dict[str, Any]],
) -> bool:
    """Add a step the agent reports to the exposure's event log; False for
    one already recorded under the same sequence number."""
    seen = (
        await session.execute(
            select(ExposureEventRow.seq).where(
                ExposureEventRow.exposure_id == exposure.id, ExposureEventRow.agent_seq == seq
            )
        )
    ).first()
    if seen is not None:
        return False
    await exposures.emit_exposure_event(
        session, exposure.id, "agent_step", AGENT,
        {"version": version, "step": step, "state": state, "message": message, "detail": detail or {}},
        agent_seq=seq,
    )
    return True


async def apply_agent_result(
    session: AsyncSession, exposure: ExposureRow, *, version: int, phase: ExposurePhase, ok: bool,
    plan: Optional[dict[str, Any]] = None, deployment: Optional[dict[str, Any]] = None,
    step: Optional[str] = None, message: Optional[str] = None,
) -> bool:
    """Apply the agent's outcome of a phase; False, and nothing changes, for a
    result about another version or a status the exposure has left, which
    covers a repeat too."""
    if version != exposure.version or exposure.status != phase.value:
        return False
    if not ok:
        exposure.status = ExposureStatus.failed.value
        exposure.failed_phase = phase.value
        exposure.failed_step = step
        exposure.failed_message = message
        await exposures.emit_exposure_event(
            session, exposure.id, f"{phase.value}_failed", AGENT, {"step": step, "message": message}
        )
        return True
    if phase is ExposurePhase.planning:
        if plan is None:
            raise ValueError("a planning result needs its plan")
        exposure.plan = plan
        exposure.plan_hash = plan_hash(plan)
        exposure.plan_version = version
        exposure.status = ExposureStatus.awaiting_confirmation.value
        await exposures.emit_exposure_event(
            session, exposure.id, "plan_ready", AGENT,
            {"version": version, "plan_hash": exposure.plan_hash, "summary": plan.get("summary", {})},
        )
    elif phase is ExposurePhase.cancelling:
        if exposure.superseded_by_id:
            exposure.status = ExposureStatus.superseded.value
            await exposures.emit_exposure_event(
                session, exposure.id, "exposure_superseded", AGENT, {"by": exposure.superseded_by_id}
            )
        else:
            exposure.status = ExposureStatus.cancelled.value
            await exposures.emit_exposure_event(session, exposure.id, "exposure_cancelled", AGENT, {})
    else:
        if deployment is None:
            raise ValueError("a deploying result needs the deployment's references")
        await _deployed(session, exposure, deployment)
    return True


async def _deployed(session: AsyncSession, exposure: ExposureRow, deployment: dict[str, Any]) -> None:
    """`deploying` to `deployed` (docs/exposure-design.md, Order of execution,
    step 6): register each origin the plan published, with the URL that
    replaces it, take those origins out of the other open exposures'
    groupings, and tell the app's other open exposures, which could not be
    planned while this one deployed."""
    registered, kept, origins = await _register_origins(session, exposure)
    exposure.status = ExposureStatus.deployed.value
    exposure.deployed_at = datetime.now(timezone.utc)
    exposure.deployment = {**deployment, "registered": registered, "already_registered": kept}
    await exposures.emit_exposure_event(
        session, exposure.id, "origins_registered", AGENT,
        {"registered": registered, "already_registered": kept},
    )
    # This one is deployed before the others are looked up.
    await session.flush()
    await exposures.drop_published_from_groupings(session, origins, by=exposure.id, actor=AGENT)
    await exposures.notify_open_exposures(
        session, "earlier_exposure_deployed", AGENT, {"by": exposure.id}, app_id=exposure.app_id
    )
    await exposures.emit_exposure_event(
        session, exposure.id, "exposure_deployed", AGENT, {"public_url": deployment.get("public_url")}
    )


async def _register_origins(
    session: AsyncSession, exposure: ExposureRow
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[exposures.Origin]]:
    """Add each origin the confirmed plan published to the registry, as this
    exposure's entry, with the URL of the VIP that publishes it: its
    services', and the app's own, at the app's public URL, so that another
    app that calls this one reaches it through its VIP rather than getting a
    second one. Returns what was registered, what someone else registered
    since the plan, which keeps its entry and the URL it has, and the origins
    registered.

    The app's origin is skipped when its entry already has the app's public
    URL: an earlier exposure of the app registered it, with the same VIP."""
    plan = exposure.plan or {}
    url_of = {
        s["service_id"]: s["url"]
        for vip in plan.get("vips", [])
        for s in vip.get("services", [])
    }
    services = (
        await session.execute(
            select(ServiceRow)
            .where(ServiceRow.scan_id == exposure.scan_id, ServiceRow.id.in_(list(url_of)))
            .order_by(ServiceRow.host, ServiceRow.port, ServiceRow.scheme)
        )
    ).scalars()
    publishing = [(exposures.origin_of(service), url_of[service.id], False) for service in services]
    app = await session.get(AppRow, exposure.app_id)
    public_url = plan.get("app", {}).get("public_url")
    if public_url:
        publishing.append((_origin_of_url(app.url), public_url, True))

    registry = await exposures.load_registry(session)
    registered, kept, origins = [], [], []
    for origin, url, is_app in publishing:
        item = {"origin": exposures.format_origin(origin), "url": url}
        entry = registry.get(origin)
        if entry is not None and is_app and entry.url == url:
            continue
        if entry is not None and entry.exposure_id != exposure.id:
            kept.append({**item, "url": entry.url})
            continue
        if entry is None:
            scheme, host, port = origin
            try:
                async with session.begin_nested():
                    session.add(PublishedOriginRow(
                        id="pub_" + uuid.uuid4().hex[:10],
                        scheme=scheme,
                        host=host,
                        port=port,
                        note=f"{'app VIP' if is_app else 'VIP'} of exposure {exposure.id}",
                        added_by=AGENT,
                        url=url,
                        exposure_id=exposure.id,
                    ))
            except IntegrityError:
                # Registered by hand a moment ago; that entry stands.
                kept.append({**item, "url": None})
                continue
        registered.append(item)
        origins.append(origin)
    return registered, kept, origins


def _origin_of_url(url: str) -> exposures.Origin:
    """(scheme, host, port) of a URL, the port made explicit, as the services table keys an origin."""
    parts = urlsplit(url)
    return (parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))
