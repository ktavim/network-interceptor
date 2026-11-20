"""An exposure's lifecycle past grouping: requesting a plan, the agent's
protocol, confirming, failing and retrying, cancelling, and what a new
submission does to an exposure that holds something. Against a real Postgres.
Set TEST_DATABASE_URL to run."""
import pytest
from fastapi import HTTPException
from sqlalchemy import select, update

from api.models import AgentResultRequest, AgentStepRequest, ConfirmRequest, VersionRequest
from api.routes_agent import pending, report_result, report_step
from api.routes_exposures import cancel_exposure, confirm_plan, request_plan, retry_exposure
from api.routes_scans import submit_scan
from core.db import ExposureRow, PublishedOriginRow

from .test_exposures import _detail, _events, _register, _request, _save, _scan, _submitted, svc

PLAN = {"summary": {"add": 3, "change": 0, "destroy": 0}, "vips": [{"ip": "203.0.113.21"}]}


async def _refused(call) -> HTTPException:
    with pytest.raises(HTTPException) as e:
        await call
    return e.value


async def _plan(factory, exposure_id, version=1):
    return await request_plan(exposure_id, VersionRequest(version=version), _request(factory))


async def _result(factory, exposure_id, version, phase, outcome="ok", **fields):
    body = AgentResultRequest(version=version, phase=phase, outcome=outcome, **fields)
    return (await report_result(exposure_id, body, _request(factory))).applied


async def _planned(factory, services=None):
    """An exposure the agent has planned: (app id, exposure detail)."""
    app_id, _, exposure = await _submitted(factory, services or [svc("a")])
    await _plan(factory, exposure.id)
    assert await _result(factory, exposure.id, 1, "planning", plan=PLAN)
    return app_id, await _detail(factory, exposure.id)


async def _set_status(factory, exposure_id, status):
    async with factory() as session:
        await session.execute(update(ExposureRow).where(ExposureRow.id == exposure_id).values(status=status))
        await session.commit()


class TestRequestPlan:
    async def test_grouping_to_planning(self, factory):
        _, _, exposure = await _submitted(factory, [svc("a")])
        detail = await _plan(factory, exposure.id)
        assert (detail.status, detail.version, detail.plan) == ("planning", 1, None)
        assert (await _events(factory, exposure.id))[-1] == ("plan_requested", "jchen", {"version": 1})

    async def test_refused_with_the_reasons_while_blocked(self, factory):
        _, _, exposure = await _submitted(factory, [svc("a", auth="kerberos")])
        error = await _refused(_plan(factory, exposure.id))
        assert error.status_code == 409
        assert [n["code"] for n in error.detail["blocked_by"]] == ["kerberos_unsupported"]
        assert (await _detail(factory, exposure.id)).status == "grouping"

    async def test_refused_for_a_stale_version(self, factory):
        _, _, exposure = await _submitted(factory, [svc("a")])
        error = await _refused(_plan(factory, exposure.id, version=7))
        assert (error.status_code, error.detail["version"]) == (409, 1)


class TestAgentProtocol:
    async def test_pending_carries_what_planning_needs(self, factory):
        entry = await _register(factory, "p", url="https://p.example.com")
        _, _, exposure = await _submitted(factory, [
            svc("b", auth="oauth"), svc("a"),
            svc("p", severity="published", auth="ntlm", published_origin_id=entry),
        ])
        await _plan(factory, exposure.id)
        [item] = await pending(_request(factory))
        assert (item["id"], item["status"], item["version"]) == (exposure.id, "planning", 1)
        work = item["planning"]
        assert work["app"]["url"] == "https://app.internal"
        assert [[(s["host"], s["auth_method"], s["ips"]) for s in g["services"]] for g in work["groups"]] == [
            [("a", "bearer", ["10.0.0.1"])], [("b", "oauth", ["10.0.0.1"])],
        ]
        assert work["published"] == [{"scheme": "https", "host": "p", "port": 443, "url": "https://p.example.com"}]

    async def test_a_step_is_recorded_once(self, factory):
        _, _, exposure = await _submitted(factory, [svc("a")])
        await _plan(factory, exposure.id)
        step = AgentStepRequest(seq=0, version=1, step="reserve_ips", state="done", message="203.0.113.21")
        await report_step(exposure.id, step, _request(factory))
        await report_step(exposure.id, step, _request(factory))
        steps = [e for e in await _events(factory, exposure.id) if e[0] == "agent_step"]
        assert steps == [("agent_step", "agent", {
            "version": 1, "step": "reserve_ips", "state": "done", "message": "203.0.113.21", "detail": {},
        })]

    async def test_a_plan_awaits_confirmation_and_a_repeat_or_stale_result_is_dropped(self, factory):
        _, detail = await _planned(factory)
        assert (detail.status, detail.plan, detail.plan_version) == ("awaiting_confirmation", PLAN, 1)
        assert detail.plan_hash.startswith("sha256:")
        assert not await _result(factory, detail.id, 1, "planning", plan={"other": 1})
        assert (await _detail(factory, detail.id)).plan == PLAN

    async def test_a_result_for_a_version_the_admin_moved_past_is_dropped(self, factory):
        _, _, exposure = await _submitted(factory, [svc("a")])
        await _plan(factory, exposure.id)
        ids = [s.id for s in (await _detail(factory, exposure.id)).services]
        await _save(factory, exposure.id, 1, [ids])  # back to grouping, version 2
        assert not await _result(factory, exposure.id, 1, "planning", plan=PLAN)
        detail = await _detail(factory, exposure.id)
        assert (detail.status, detail.plan) == ("grouping", None)

    async def test_a_deploy_result_needs_its_references(self, factory):
        _, detail = await _planned(factory)
        await confirm_plan(detail.id, ConfirmRequest(version=1, plan_hash=detail.plan_hash), _request(factory))
        error = await _refused(_result(factory, detail.id, 1, "deploying"))
        assert error.status_code == 422
        assert (await _detail(factory, detail.id)).status == "deploying"


class TestConfirm:
    async def test_the_exact_plan_moves_to_deploying(self, factory):
        _, detail = await _planned(factory)
        error = await _refused(confirm_plan(
            detail.id, ConfirmRequest(version=1, plan_hash="sha256:nope"), _request(factory)
        ))
        assert (error.status_code, error.detail["plan_hash"]) == (409, detail.plan_hash)
        confirmed = await confirm_plan(
            detail.id, ConfirmRequest(version=1, plan_hash=detail.plan_hash), _request(factory)
        )
        assert (confirmed.status, confirmed.confirmed_by) == ("deploying", "jchen")
        assert confirmed.confirmed_at

    async def test_changing_the_grouping_drops_the_plan(self, factory):
        _, detail = await _planned(factory)
        after = await _save(factory, detail.id, 1, [[s.id for s in detail.services]])
        assert (after.status, after.plan, after.plan_hash) == ("grouping", None, None)


class TestFailAndRetry:
    async def test_a_failed_plan_says_where_and_retries(self, factory):
        _, _, exposure = await _submitted(factory, [svc("a")])
        await _plan(factory, exposure.id)
        assert await _result(factory, exposure.id, 1, "planning", outcome="failed",
                             step="dry_run", message="AS3 refused the declaration")
        failed = await _detail(factory, exposure.id)
        assert failed.status == "failed"
        assert (failed.failed.phase, failed.failed.step, failed.failed.message) == (
            "planning", "dry_run", "AS3 refused the declaration",
        )
        retried = await retry_exposure(exposure.id, VersionRequest(version=1), _request(factory))
        assert (retried.status, retried.failed) == ("planning", None)


class TestCancel:
    async def test_never_planned_closes_at_once(self, factory):
        _, _, exposure = await _submitted(factory, [svc("a")])
        detail = await cancel_exposure(exposure.id, VersionRequest(version=1), _request(factory))
        assert (detail.status, detail.version) == ("cancelled", 2)

    async def test_planned_goes_through_the_agent(self, factory):
        _, detail = await _planned(factory)
        cancelling = await cancel_exposure(detail.id, VersionRequest(version=1), _request(factory))
        assert (cancelling.status, cancelling.version) == ("cancelling", 2)
        [item] = await pending(_request(factory))
        assert item["cancelling"] == {"superseded_by": None}
        assert await _result(factory, detail.id, 2, "cancelling")
        assert (await _detail(factory, detail.id)).status == "cancelled"

    async def test_refused_while_deploying(self, factory):
        _, detail = await _planned(factory)
        await confirm_plan(detail.id, ConfirmRequest(version=1, plan_hash=detail.plan_hash), _request(factory))
        error = await _refused(cancel_exposure(detail.id, VersionRequest(version=1), _request(factory)))
        assert (error.status_code, error.detail["status"]) == (409, "deploying")


class TestNewSubmission:
    async def test_a_planned_exposure_is_superseded_through_cancelling(self, factory):
        app_id, old = await _planned(factory, [svc("a"), svc("b")])
        _, scan_id = await _scan(factory, [svc("a"), svc("c")], app_id=app_id)
        await submit_scan(scan_id, _request(factory))
        old_now = await _detail(factory, old.id)
        assert (old_now.status, old_now.version) == ("cancelling", 2)
        new = await _detail(factory, old_now.superseded_by)
        assert (new.status, new.supersedes) == ("grouping", old.id)
        assert (await _events(factory, old.id))[-1] == (
            "supersede_requested", "jchen", {"by": new.id, "version": 2},
        )
        assert await _result(factory, old.id, 2, "cancelling")
        assert (await _detail(factory, old.id)).status == "superseded"
        assert (await _events(factory, old.id))[-1] == ("exposure_superseded", "agent", {"by": new.id})

    async def test_a_deploying_exposure_is_left_to_finish(self, factory):
        app_id, old = await _planned(factory)
        await confirm_plan(old.id, ConfirmRequest(version=1, plan_hash=old.plan_hash), _request(factory))
        _, scan_id = await _scan(factory, [svc("a"), svc("b")], app_id=app_id)
        await submit_scan(scan_id, _request(factory))
        assert (await _detail(factory, old.id)).status == "deploying"
        async with factory() as session:
            new_id = (await session.execute(
                ExposureRow.__table__.select().where(ExposureRow.scan_id == scan_id)
            )).first().id
        new = await _detail(factory, new_id)
        assert (new.status, new.supersedes) == ("grouping", None)
        assert [(n.code, old.id in n.message) for n in new.blocked_by] == [("earlier_exposure_deploying", True)]
        error = await _refused(_plan(factory, new_id))
        assert [n["code"] for n in error.detail["blocked_by"]] == ["earlier_exposure_deploying"]


def _real_plan(detail) -> dict:
    """A plan the shape the agent sends, publishing each grouped service at
    https://<host>.example.com."""
    by_id = {s.id: s for s in detail.services}
    return {
        "app": {"public_url": "https://payroll.example.com"},
        "summary": {"add": 3, "change": 0, "destroy": 0},
        "vips": [
            {
                "group_id": g.id,
                "ip": f"203.0.113.{i + 1}",
                "services": [
                    {"service_id": sid, "url": f"https://{by_id[sid].host}.example.com"} for sid in g.service_ids
                ],
            }
            for i, g in enumerate(detail.groups)
        ],
    }


DEPLOYMENT = {
    "partition": "exp_app",
    "public_url": "https://payroll.example.com",
    "virtual_servers": ["/exp_app/app/vs_app"],
    "dns_records": [{"name": "payroll.example.com", "type": "A", "target": "203.0.113.9", "id": "rec_1"}],
}


async def _deploying(factory, services, *, app_id=None, app_url="https://app.internal"):
    """An exposure confirmed with a real-shaped plan, of a new app unless
    `app_id` names one: (app id, detail)."""
    if app_id is None:
        app_id, _, exposure = await _submitted(factory, services, app_url=app_url)
    else:
        _, scan_id = await _scan(factory, services, app_id=app_id)
        await submit_scan(scan_id, _request(factory))
        exposure = await _exposure_by_scan(factory, scan_id)
    await _plan(factory, exposure.id)
    detail = await _detail(factory, exposure.id)
    assert await _result(factory, exposure.id, 1, "planning", plan=_real_plan(detail))
    detail = await _detail(factory, exposure.id)
    await confirm_plan(detail.id, ConfirmRequest(version=1, plan_hash=detail.plan_hash), _request(factory))
    return app_id, await _detail(factory, exposure.id)


async def _exposure_by_scan(factory, scan_id) -> ExposureRow:
    async with factory() as session:
        return (await session.execute(select(ExposureRow).where(ExposureRow.scan_id == scan_id))).scalar_one()


async def _registry(factory) -> list[tuple[str, str, str]]:
    async with factory() as session:
        rows = await session.execute(
            select(PublishedOriginRow).where(PublishedOriginRow.removed_at.is_(None)).order_by(PublishedOriginRow.host)
        )
        return [(r.host, r.url, r.exposure_id) for r in rows.scalars()]


class TestDeploy:
    async def test_the_agent_gets_the_confirmed_hash_only(self, factory):
        _, detail = await _deploying(factory, [svc("a")])
        [item] = await pending(_request(factory))
        assert (item["status"], item["deploying"]) == ("deploying", {"plan_hash": detail.plan_hash})

    async def test_a_deploy_registers_its_origins_and_closes(self, factory):
        _, detail = await _deploying(factory, [svc("b"), svc("a")])
        assert await _result(factory, detail.id, 1, "deploying", deployment=DEPLOYMENT)
        deployed = await _detail(factory, detail.id)
        assert (deployed.status, deployed.deployed_at is not None) == ("deployed", True)
        assert deployed.deployment == {
            **DEPLOYMENT,
            "registered": [
                {"origin": "https://a", "url": "https://a.example.com"},
                {"origin": "https://b", "url": "https://b.example.com"},
                # The app's own, for the apps that call it.
                {"origin": "https://app.internal", "url": "https://payroll.example.com"},
            ],
            "already_registered": [],
        }
        assert await _registry(factory) == [
            ("a", "https://a.example.com", detail.id),
            ("app.internal", "https://payroll.example.com", detail.id),
            ("b", "https://b.example.com", detail.id),
        ]
        # Its own entries do not make its services published.
        assert {s.scope for s in deployed.services} == {"needs_vip"}
        assert deployed.blocked_by == []
        assert [e[0] for e in (await _events(factory, detail.id))[-2:]] == ["origins_registered", "exposure_deployed"]
        # A repeat is dropped.
        assert not await _result(factory, detail.id, 1, "deploying", deployment=DEPLOYMENT)

    async def test_an_origin_registered_since_the_plan_keeps_its_entry(self, factory):
        _, detail = await _deploying(factory, [svc("a")])
        await _register(factory, "a", url="https://by-hand.example.com")
        assert await _result(factory, detail.id, 1, "deploying", deployment=DEPLOYMENT)
        deployed = await _detail(factory, detail.id)
        assert deployed.deployment["registered"] == [
            {"origin": "https://app.internal", "url": "https://payroll.example.com"},
        ]
        assert deployed.deployment["already_registered"] == [
            {"origin": "https://a", "url": "https://by-hand.example.com"},
        ]
        assert await _registry(factory) == [
            ("a", "https://by-hand.example.com", None), ("app.internal", "https://payroll.example.com", detail.id),
        ]

    async def test_the_newer_submission_is_unblocked_and_loses_what_was_published(self, factory):
        app_id, old = await _deploying(factory, [svc("a"), svc("b")])
        _, scan_id = await _scan(factory, [svc("a"), svc("c")], app_id=app_id)
        await submit_scan(scan_id, _request(factory))
        new_id = (await _exposure_by_scan(factory, scan_id)).id
        before = await _detail(factory, new_id)
        assert [n.code for n in before.blocked_by] == ["earlier_exposure_deploying"]
        assert len([sid for g in before.groups for sid in g.service_ids]) == 2

        assert await _result(factory, old.id, 1, "deploying", deployment=DEPLOYMENT)
        after = await _detail(factory, new_id)
        assert (after.status, after.version, after.blocked_by) == ("grouping", 2, [])
        by_host = {s.host: s for s in after.services}
        assert (by_host["a"].scope, by_host["a"].registry_entry.url) == ("published", "https://a.example.com")
        assert [g.service_ids for g in after.groups] == [[by_host["c"].id]]
        events = await _events(factory, new_id)
        assert [e[:2] for e in events[-2:]] == [("grouping_pruned", "agent"), ("earlier_exposure_deployed", "agent")]
        assert events[-2][2] == {"version": 2, "by": old.id, "origins": ["https://a"]}

        await _plan(factory, new_id, version=2)
        item = next(i for i in await pending(_request(factory)) if i["id"] == new_id)
        assert [[s["host"] for s in g["services"]] for g in item["planning"]["groups"]] == [["c"]]
        assert item["planning"]["published"] == [
            {"scheme": "https", "host": "a", "port": 443, "url": "https://a.example.com"},
        ]

    async def test_another_apps_plan_for_the_same_origin_is_dropped(self, factory):
        _, first = await _deploying(factory, [svc("shared")])
        _, other = await _planned(factory, [svc("shared"), svc("d")])
        assert other.status == "awaiting_confirmation"
        assert await _result(factory, first.id, 1, "deploying", deployment=DEPLOYMENT)
        after = await _detail(factory, other.id)
        assert (after.status, after.version, after.plan) == ("grouping", 2, None)
        assert [len(g.service_ids) for g in after.groups] == [1]
        assert (await _events(factory, other.id))[-1] == ("grouping_pruned", "agent", {
            "version": 2, "by": first.id, "origins": ["https://shared"], "from_status": "awaiting_confirmation",
        })
        # The agent's plan for the old version is dropped when it arrives.
        assert not await _result(factory, other.id, 1, "planning", plan=PLAN)

    async def test_another_app_that_calls_this_one_gets_its_vip(self, factory):
        _, caller = await _planned(factory, [svc("payroll.internal"), svc("d")])
        _, payroll = await _deploying(factory, [svc("a")], app_url="https://payroll.internal")
        assert await _result(factory, payroll.id, 1, "deploying", deployment=DEPLOYMENT)
        after = await _detail(factory, caller.id)
        by_host = {s.host: s for s in after.services}
        assert (by_host["payroll.internal"].scope, by_host["payroll.internal"].registry_entry.url) == (
            "published", "https://payroll.example.com",
        )
        assert (after.status, [g.service_ids for g in after.groups]) == ("grouping", [[by_host["d"].id]])

    async def test_a_later_exposure_of_the_app_leaves_its_entry_alone(self, factory):
        app_id, first = await _deploying(factory, [svc("a")])
        assert await _result(factory, first.id, 1, "deploying", deployment=DEPLOYMENT)
        _, second = await _deploying(factory, [svc("a"), svc("c")], app_id=app_id)
        assert await _result(factory, second.id, 1, "deploying", deployment=DEPLOYMENT)
        deployed = await _detail(factory, second.id)
        assert deployed.deployment["registered"] == [{"origin": "https://c", "url": "https://c.example.com"}]
        assert deployed.deployment["already_registered"] == []
        assert ("app.internal", "https://payroll.example.com", first.id) in await _registry(factory)

    async def test_a_failed_deploy_retries_then_cancels(self, factory):
        _, detail = await _deploying(factory, [svc("a")])
        assert await _result(factory, detail.id, 1, "deploying", outcome="failed",
                             step="verify", message="vs_app is down")
        failed = await _detail(factory, detail.id)
        assert (failed.status, failed.failed.phase, failed.failed.step) == ("failed", "deploying", "verify")
        retried = await retry_exposure(detail.id, VersionRequest(version=1), _request(factory))
        assert retried.status == "deploying"
        [item] = await pending(_request(factory))
        assert item["deploying"] == {"plan_hash": detail.plan_hash}
        assert await _result(factory, detail.id, 1, "deploying", outcome="failed", step="dns", message="zone refused")
        cancelling = await cancel_exposure(detail.id, VersionRequest(version=1), _request(factory))
        assert (cancelling.status, cancelling.version) == ("cancelling", 2)
        assert await _result(factory, detail.id, 2, "cancelling")
        assert (await _detail(factory, detail.id)).status == "cancelled"
        assert await _registry(factory) == []

