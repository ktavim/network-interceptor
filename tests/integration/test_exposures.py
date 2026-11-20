"""Exposures: created on submit, superseded by the next submission, and read
by the console's queue, history and workspace endpoints. Against a real
Postgres. Set TEST_DATABASE_URL to run."""
import asyncio
import json
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import select, update

from api.models import GroupInput, PatchPublishedOriginRequest, SaveGroupingRequest
from api.routes_exposures import exposure_events, get_exposure, list_exposures, save_groups
from api.routes_published_origins import patch_published_origin
from api.routes_scans import submit_scan
from api.sse import EventBus
from core.db import (
    AppRow,
    ExposureEventRow,
    ExposureGroupMemberRow,
    ExposureRow,
    PublishedOriginRow,
    ScanRow,
    ServiceFindingRow,
    ServiceRow,
)
from core.enums import ExposureStatus
from core.exposures import emit_exposure_event

BOTH = ("interceptor", "tracer")


def _request(factory) -> SimpleNamespace:
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(session_factory=factory)))


def svc(host, *, scheme="https", port=443, auth="bearer", severity="cleared", excluded=False,
        found_by=BOTH, published_origin_id=None) -> dict:
    return dict(scheme=scheme, host=host, port=port, auth=auth, severity=severity,
                excluded=excluded, found_by=found_by, published_origin_id=published_origin_id)


async def _scan(factory, services, *, app_id=None, app_url="https://app.internal") -> tuple[str, str]:
    """A completed scan with `services`, on a new app unless `app_id` names
    one. Returns (app id, scan id)."""
    new_app = app_id is None
    app_id = app_id or uuid.uuid4().hex
    scan_id = uuid.uuid4().hex
    async with factory() as session:
        if new_app:
            session.add(AppRow(id=app_id, name="Payroll", url=app_url, owner_ad_group="g"))
        session.add(ScanRow(id=scan_id, app_id=app_id, name="Payroll", url=app_url or "http://x",
                            status="completed", started_by="test"))
        await session.flush()
        for s in services:
            service_id = uuid.uuid4().hex
            session.add(ServiceRow(
                id=service_id, scan_id=scan_id, scheme=s["scheme"], host=s["host"], port=s["port"],
                auth_method=s["auth"], severity=s["severity"], excluded=s["excluded"],
                published_origin_id=s["published_origin_id"], ips=["10.0.0.1"],
            ))
            await session.flush()
            for scanner in s["found_by"]:
                session.add(ServiceFindingRow(
                    service_id=service_id, scanner=scanner, auth_method=s["auth"], url_count=1,
                ))
        await session.commit()
    return app_id, scan_id


async def _submitted(factory, services, **kwargs) -> tuple[str, str, ExposureRow]:
    app_id, scan_id = await _scan(factory, services, **kwargs)
    await submit_scan(scan_id, _request(factory))
    return app_id, scan_id, await _exposure_of(factory, scan_id)


async def _exposure_of(factory, scan_id) -> ExposureRow:
    async with factory() as session:
        return (await session.execute(select(ExposureRow).where(ExposureRow.scan_id == scan_id))).scalar_one()


async def _register(factory, host, *, url=None, scheme="https", port=443) -> str:
    entry_id = "pub_" + uuid.uuid4().hex[:10]
    async with factory() as session:
        session.add(PublishedOriginRow(id=entry_id, scheme=scheme, host=host, port=port,
                                       added_by="test", url=url))
        await session.commit()
    return entry_id


async def _events(factory, exposure_id) -> list[tuple[str, str, dict]]:
    async with factory() as session:
        rows = await session.execute(
            select(ExposureEventRow)
            .where(ExposureEventRow.exposure_id == exposure_id)
            .order_by(ExposureEventRow.seq)
        )
        return [(r.type, r.actor, r.payload) for r in rows.scalars()]


def _hosts(detail, group) -> list[str]:
    by_id = {s.id: s for s in detail.services}
    return [f"{by_id[i].host}:{by_id[i].port}" for i in group.service_ids]


async def _detail(factory, exposure_id):
    return await get_exposure(exposure_id, _request(factory))


async def _queue(factory, status=None):
    return await list_exposures(_request(factory), status=status)


class TestCreatedOnSubmit:
    async def test_one_exposure_pinned_to_the_scan_in_grouping(self, factory):
        _, scan_id, exposure = await _submitted(factory, [svc("a")])
        assert (exposure.scan_id, exposure.status, exposure.version) == (scan_id, "grouping", 1)
        assert exposure.id.startswith("exp_")
        assert await _events(factory, exposure.id) == [
            ("exposure_created", "jchen", {"scan_id": scan_id, "supersedes": None}),
        ]

    async def test_the_default_grouping_is_one_vip_per_host(self, factory):
        _, _, exposure = await _submitted(factory, [
            svc("b"), svc("a", port=8443), svc("a"), svc("x", excluded=True, severity="blocker", auth="ntlm"),
        ])
        detail = await _detail(factory, exposure.id)
        assert [_hosts(detail, g) for g in detail.groups] == [["a:443", "a:8443"], ["b:443"]]

    async def test_an_origin_registered_after_the_scan_gets_no_group(self, factory):
        app_id, scan_id = await _scan(factory, [svc("a"), svc("p")])
        await _register(factory, "p", url="https://p.example.com")
        await submit_scan(scan_id, _request(factory))
        detail = await _detail(factory, (await _exposure_of(factory, scan_id)).id)
        assert [_hosts(detail, g) for g in detail.groups] == [["a:443"]]

    async def test_a_submit_that_fails_creates_no_exposure(self, factory):
        _, scan_id = await _scan(factory, [svc("a", severity="blocker", auth="ntlm")])
        with pytest.raises(HTTPException):
            await submit_scan(scan_id, _request(factory))
        async with factory() as session:
            assert (await session.execute(select(ExposureRow))).first() is None


class TestSupersede:
    async def test_a_new_submission_supersedes_the_open_exposure(self, factory):
        app_id, _, old = await _submitted(factory, [svc("a"), svc("b"), svc("c")])
        # The admin put a and b on one VIP.
        async with factory() as session:
            members = {m.service_id: m for m in (await session.execute(
                select(ExposureGroupMemberRow).where(ExposureGroupMemberRow.exposure_id == old.id)
            )).scalars()}
            hosts = {s.id: s.host for s in (await session.execute(
                select(ServiceRow).where(ServiceRow.id.in_(members))
            )).scalars()}
            a_group = next(m.group_id for sid, m in members.items() if hosts[sid] == "a")
            b_id = next(sid for sid in members if hosts[sid] == "b")
            await session.execute(
                update(ExposureGroupMemberRow)
                .where(ExposureGroupMemberRow.exposure_id == old.id, ExposureGroupMemberRow.service_id == b_id)
                .values(group_id=a_group)
            )
            await session.commit()

        # The new scan drops c and adds d, and a second port on b.
        _, new_scan_id = await _scan(factory, [svc("a"), svc("b"), svc("b", port=8443), svc("d")], app_id=app_id)
        await submit_scan(new_scan_id, _request(factory))
        new = await _exposure_of(factory, new_scan_id)

        old_detail = await _detail(factory, old.id)
        assert (old_detail.status, old_detail.superseded_by) == ("superseded", new.id)
        new_detail = await _detail(factory, new.id)
        assert (new_detail.status, new_detail.supersedes) == ("grouping", old.id)
        assert [_hosts(new_detail, g) for g in new_detail.groups] == [
            ["a:443", "b:443", "b:8443"], ["d:443"],
        ]
        assert (await _events(factory, old.id))[-1] == ("exposure_superseded", "jchen", {"by": new.id})
        assert (await _events(factory, new.id))[0][2]["supersedes"] == old.id

        assert [e.id for e in await _queue(factory)] == [new.id]
        assert [e.id for e in await _queue(factory, [ExposureStatus.superseded])] == [old.id]


class TestQueue:
    async def test_open_exposures_oldest_submission_first(self, factory):
        _, _, first = await _submitted(factory, [svc("a"), svc("b")])
        _, _, second = await _submitted(factory, [svc("c", auth="kerberos")])
        queue = await _queue(factory)
        assert [(e.id, e.needs_vip_count, e.blocked) for e in queue] == [
            (first.id, 2, False), (second.id, 1, True),
        ]
        assert (queue[0].app.name, queue[0].submitted_by, queue[0].status) == ("Payroll", "jchen", "grouping")

    async def test_history_newest_first(self, factory):
        _, _, first = await _submitted(factory, [svc("a")])
        _, _, second = await _submitted(factory, [svc("a")])
        async with factory() as session:
            await session.execute(update(ExposureRow).values(status="cancelled"))
            await session.commit()
        assert await _queue(factory) == []
        history = await _queue(factory, [ExposureStatus.cancelled, ExposureStatus.deployed])
        assert [e.id for e in history] == [second.id, first.id]


class TestWorkspace:
    async def test_unknown_exposure_is_404(self, factory):
        with pytest.raises(HTTPException) as e:
            await _detail(factory, "exp_nope")
        assert e.value.status_code == 404

    async def test_scopes_warnings_and_what_blocks_planning(self, factory):
        entry = await _register(factory, "p")
        _, scan_id, exposure = await _submitted(factory, [
            svc("a", found_by=("interceptor",)),
            svc("k", auth="kerberos"),
            svc("l", auth="login_redirect"),
            svc("p", severity="published", auth="ntlm", published_origin_id=entry),
            svc("x", severity="blocker", auth="ntlm", excluded=True),
        ])
        detail = await _detail(factory, exposure.id)
        by_host = {s.host: s for s in detail.services}
        assert {h: s.scope for h, s in by_host.items()} == {
            "a": "needs_vip", "k": "needs_vip", "l": "needs_vip", "p": "published", "x": "excluded",
        }
        assert [w.code for w in by_host["a"].warnings] == ["interceptor_only"]
        assert [w.code for w in by_host["l"].warnings] == ["login_redirect"]
        assert by_host["p"].registry_entry.id == entry and by_host["p"].group_id is None
        assert by_host["a"].group_id in {g.id for g in detail.groups}
        assert [(n.code, n.service_id) for n in detail.blocked_by] == [
            ("kerberos_unsupported", by_host["k"].id),
            ("published_url_missing", by_host["p"].id),
        ]
        assert (detail.needs_vip_count, detail.blocked, detail.version) == (3, True, 1)
        assert (detail.app.url, detail.scan_id) == ("https://app.internal", scan_id)

    async def test_a_service_published_since_leaves_its_group(self, factory):
        _, _, exposure = await _submitted(factory, [svc("a"), svc("b")])
        await _register(factory, "b", url="https://b.example.com")
        detail = await _detail(factory, exposure.id)
        b = next(s for s in detail.services if s.host == "b")
        assert (b.scope, b.group_id, b.registry_entry.url) == ("published", None, "https://b.example.com")
        assert [_hosts(detail, g) for g in detail.groups] == [["a:443"], []]
        assert (detail.needs_vip_count, detail.blocked_by) == (1, [])

    async def test_a_service_whose_entry_was_removed_since(self, factory):
        entry = await _register(factory, "p")
        _, _, exposure = await _submitted(factory, [
            svc("p", severity="published", auth="ntlm", published_origin_id=entry),
        ])
        async with factory() as session:
            await session.execute(
                update(PublishedOriginRow).where(PublishedOriginRow.id == entry)
                .values(removed_at=PublishedOriginRow.added_at, removed_by="test")
            )
            await session.commit()
        detail = await _detail(factory, exposure.id)
        [p] = detail.services
        assert (p.scope, p.registry_entry.id) == ("unresolved", entry)
        assert [n.code for n in detail.blocked_by] == ["published_origin_removed"]


def _stream_request(factory, bus=None, **headers) -> SimpleNamespace:
    async def is_disconnected():
        return False

    state = SimpleNamespace(session_factory=factory, event_bus=bus or EventBus(factory))
    return SimpleNamespace(app=SimpleNamespace(state=state), headers=headers, is_disconnected=is_disconnected)


async def _stream(factory, exposure_id, **headers) -> list[dict]:
    """The events GET /exposures/{id}/events sends before it closes the stream."""
    response = await exposure_events(exposure_id, _stream_request(factory, **headers))
    async with asyncio.timeout(5):
        return [json.loads(event["data"]) async for event in response.body_iterator if "data" in event]


async def _emit(factory, exposure_id, event_type, actor="mlevi", payload=None) -> None:
    async with factory() as session:
        await emit_exposure_event(session, exposure_id, event_type, actor, payload)
        await session.commit()


class TestEventStream:
    async def test_a_closed_exposure_replays_and_ends(self, factory):
        app_id, _, old = await _submitted(factory, [svc("a")])
        _, scan_id = await _scan(factory, [svc("a")], app_id=app_id)
        await submit_scan(scan_id, _request(factory))
        events = await _stream(factory, old.id)
        assert [(e["type"], e["actor"], e["seq"]) for e in events] == [
            ("exposure_created", "jchen", "0"), ("exposure_superseded", "jchen", "1"),
        ]
        assert events[0]["exposure_id"] == old.id and events[0]["ts"] > 0

    async def test_it_resumes_after_last_event_id(self, factory):
        app_id, _, old = await _submitted(factory, [svc("a")])
        _, scan_id = await _scan(factory, [svc("a")], app_id=app_id)
        await submit_scan(scan_id, _request(factory))
        assert [e["type"] for e in await _stream(factory, old.id, **{"Last-Event-ID": "0"})] == [
            "exposure_superseded"
        ]

    async def test_an_unknown_exposure_is_404(self, factory):
        with pytest.raises(HTTPException) as e:
            await exposure_events("exp_nope", _stream_request(factory))
        assert e.value.status_code == 404

    async def test_an_open_exposure_streams_new_events_as_they_commit(self, factory, migrated_db, monkeypatch):
        # The bus LISTENs on the database DATABASE_URL names.
        monkeypatch.setenv("DATABASE_URL", migrated_db)
        _, _, exposure = await _submitted(factory, [svc("a")])
        bus = EventBus(factory)
        listening = asyncio.Event()
        wake_all = bus._wake_all
        # Called once LISTEN is in place.
        monkeypatch.setattr(bus, "_wake_all", lambda: (wake_all(), listening.set()))
        runner = asyncio.create_task(bus.run())
        try:
            async with asyncio.timeout(10):
                await listening.wait()
            response = await exposure_events(exposure.id, _stream_request(factory, bus))
            events = response.body_iterator
            async with asyncio.timeout(5):
                assert json.loads((await anext(events))["data"])["type"] == "exposure_created"
                await _emit(factory, exposure.id, "grouping_saved", payload={"version": 2})
                # Sooner than the stream's 15 s keepalive: the NOTIFY woke it.
                saved = json.loads((await anext(events))["data"])
                assert (saved["type"], saved["actor"], saved["payload"]) == ("grouping_saved", "mlevi", {"version": 2})
                await _emit(factory, exposure.id, "exposure_cancelled")
                assert json.loads((await anext(events))["data"])["type"] == "exposure_cancelled"
                # The event that closes the exposure ends its stream.
                with pytest.raises(StopAsyncIteration):
                    await anext(events)
        finally:
            runner.cancel()
            await asyncio.gather(runner, return_exceptions=True)


def _ids_by_host(detail) -> dict[str, str]:
    return {f"{s.host}:{s.port}": s.id for s in detail.services}


async def _save(factory, exposure_id, version, groups):
    """Save `groups`, each a list of service ids or (group id, service ids)."""
    body = SaveGroupingRequest(version=version, groups=[
        GroupInput(id=g[0], service_ids=g[1]) if isinstance(g, tuple) else GroupInput(service_ids=g)
        for g in groups
    ])
    return await save_groups(exposure_id, body, _request(factory))


async def _refused(call) -> HTTPException:
    with pytest.raises(HTTPException) as e:
        await call
    return e.value


class TestSaveGrouping:
    async def test_saving_replaces_the_grouping_and_bumps_the_version(self, factory):
        _, _, exposure = await _submitted(factory, [svc("a"), svc("b"), svc("c")])
        before = await _detail(factory, exposure.id)
        ids = _ids_by_host(before)
        a_group = next(g.id for g in before.groups if ids["a:443"] in g.service_ids)
        after = await _save(factory, exposure.id, 1, [
            (a_group, [ids["a:443"], ids["b:443"]]), [], [ids["c:443"]],
        ])
        assert (after.version, after.status, after.blocked_by) == (2, "grouping", [])
        assert [_hosts(after, g) for g in after.groups] == [["a:443", "b:443"], ["c:443"]]
        # The group named by id keeps it; the new one gets its own; the empty one is dropped.
        assert after.groups[0].id == a_group and after.groups[1].id not in {g.id for g in before.groups}
        assert (await _events(factory, exposure.id))[-1] == (
            "grouping_saved", "jchen", {"version": 2, "groups": 2},
        )

    async def test_a_save_against_an_older_version_is_409_with_the_current_one(self, factory):
        _, _, exposure = await _submitted(factory, [svc("a")])
        ids = _ids_by_host(await _detail(factory, exposure.id))
        await _save(factory, exposure.id, 1, [[ids["a:443"]]])
        error = await _refused(_save(factory, exposure.id, 1, [[ids["a:443"]]]))
        assert error.status_code == 409
        assert (error.detail["status"], error.detail["version"]) == ("grouping", 2)

    async def test_a_closed_exposure_cannot_be_regrouped(self, factory):
        app_id, _, old = await _submitted(factory, [svc("a")])
        ids = _ids_by_host(await _detail(factory, old.id))
        _, scan_id = await _scan(factory, [svc("a")], app_id=app_id)
        await submit_scan(scan_id, _request(factory))
        error = await _refused(_save(factory, old.id, 1, [[ids["a:443"]]]))
        assert (error.status_code, error.detail["status"]) == (409, "superseded")

    async def test_an_invalid_grouping_is_422_with_an_error_per_service(self, factory):
        _, _, exposure = await _submitted(factory, [
            svc("a"), svc("b"), svc("c"), svc("x", excluded=True, severity="blocker", auth="ntlm"),
        ])
        ids = _ids_by_host(await _detail(factory, exposure.id))
        error = await _refused(_save(factory, exposure.id, 1, [
            [ids["a:443"], ids["x:443"]], [ids["a:443"], "svc_nope"],
        ]))
        assert error.status_code == 422
        assert sorted((e["code"], e["service_id"]) for e in error.detail["errors"]) == sorted([
            ("not_in_scope", ids["x:443"]),
            ("duplicate", ids["a:443"]),
            ("unknown_service", "svc_nope"),
            ("service_ungrouped", ids["b:443"]),
            ("service_ungrouped", ids["c:443"]),
        ])
        assert (await _detail(factory, exposure.id)).version == 1

    async def test_saving_a_planned_exposure_drops_the_plan(self, factory):
        _, _, exposure = await _submitted(factory, [svc("a")])
        ids = _ids_by_host(await _detail(factory, exposure.id))
        async with factory() as session:
            await session.execute(
                update(ExposureRow).where(ExposureRow.id == exposure.id).values(status="awaiting_confirmation")
            )
            await session.commit()
        after = await _save(factory, exposure.id, 1, [[ids["a:443"]]])
        assert (after.status, after.version) == ("grouping", 2)
        assert (await _events(factory, exposure.id))[-1][2] == {
            "version": 2, "groups": 1, "from_status": "awaiting_confirmation",
        }

    async def test_unknown_exposure_is_404(self, factory):
        error = await _refused(_save(factory, "exp_nope", 1, []))
        assert error.status_code == 404


class TestFixingBlockers:
    async def test_setting_a_registry_url_clears_the_blocker_on_every_exposure_that_calls_it(self, factory):
        entry = await _register(factory, "p")
        published = dict(severity="published", auth="ntlm", published_origin_id=entry)
        _, _, first = await _submitted(factory, [svc("a"), svc("p", **published)])
        _, _, second = await _submitted(factory, [svc("p", **published)])
        _, _, unrelated = await _submitted(factory, [svc("a")])
        assert [n.code for n in (await _detail(factory, first.id)).blocked_by] == ["published_url_missing"]

        result = await patch_published_origin(
            entry, PatchPublishedOriginRequest(url="https://p.example.com"), _request(factory)
        )
        assert result.url == "https://p.example.com"
        for exposure in (first, second):
            assert (await _detail(factory, exposure.id)).blocked_by == []
            assert (await _events(factory, exposure.id))[-1] == (
                "registry_url_set", "jchen", {"origin": "https://p", "url": "https://p.example.com"},
            )
        assert [t for t, *_ in await _events(factory, unrelated.id)] == ["exposure_created"]

    async def test_a_removed_registry_entry_is_404(self, factory):
        entry = await _register(factory, "p")
        async with factory() as session:
            await session.execute(
                update(PublishedOriginRow).where(PublishedOriginRow.id == entry)
                .values(removed_at=PublishedOriginRow.added_at, removed_by="test")
            )
            await session.commit()
        error = await _refused(
            patch_published_origin(entry, PatchPublishedOriginRequest(url="https://p.example.com"), _request(factory))
        )
        assert error.status_code == 404
