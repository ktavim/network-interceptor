"""An exposure's lifecycle past grouping: requesting a plan, the agent's
protocol, confirming, failing and retrying, cancelling, and what a new
submission does to an exposure that holds something. Against a real Postgres.
Set TEST_DATABASE_URL to run."""
import pytest
from fastapi import HTTPException
from sqlalchemy import update

from api.models import AgentResultRequest, AgentStepRequest, ConfirmRequest, VersionRequest
from api.routes_agent import pending, report_result, report_step
from api.routes_exposures import cancel_exposure, confirm_plan, request_plan, retry_exposure
from api.routes_scans import submit_scan
from core.db import ExposureRow

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
        _, _, exposure = await _submitted(factory, [svc("a")], app_url=None)
        error = await _refused(_plan(factory, exposure.id))
        assert error.status_code == 409
        assert [n["code"] for n in error.detail["blocked_by"]] == ["app_url_missing"]
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

    async def test_a_deploy_result_is_not_handled_yet(self, factory):
        _, detail = await _planned(factory)
        await confirm_plan(detail.id, ConfirmRequest(version=1, plan_hash=detail.plan_hash), _request(factory))
        error = await _refused(_result(factory, detail.id, 1, "deploying"))
        assert error.status_code == 501


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
