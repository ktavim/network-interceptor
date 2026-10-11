"""The published-origins registry: its routes, and the "published" severity it
gives a service on every scan finalized while an entry is active. Against a
real Postgres. Set TEST_DATABASE_URL to run."""
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import select

from api.models import CreatePublishedOriginRequest, PatchServiceRequest, PublishedChange
from api.routes_apps import app_diff
from api.routes_published_origins import (
    create_published_origin,
    delete_published_origin,
    list_published_origins,
)
from api.routes_scans import get_scan, list_services, patch_service, submit_scan
from core.db import AppRow, ScanEventRow, ScanJobRow, ScanRow, ServiceRow
from core.enums import AuthMethod, JobStatus, Scanner
from core.jobs import finish
from core.translate import services_to_rows

INTERCEPTOR = Scanner.interceptor
HOST = "a.example"


def _request(factory) -> SimpleNamespace:
    # app_diff reads request.query_params whatever its keyword arguments.
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(session_factory=factory)), query_params={})


async def _add_scan(factory, status="running", *, app_id=None) -> tuple[str, str]:
    """A scan with an interceptor job in the scan's status, on an app of its
    own unless `app_id` names one. Returns (app id, scan id)."""
    new_app = app_id is None
    app_id = app_id or uuid.uuid4().hex
    scan_id = uuid.uuid4().hex
    async with factory() as session:
        if new_app:
            session.add(AppRow(id=app_id, name="app", url="http://x", owner_ad_group="g"))
        session.add(ScanRow(
            id=scan_id, app_id=app_id, name="app", url="http://x", status=status, started_by="test",
        ))
        session.add(ScanJobRow(
            id=uuid.uuid4().hex, scan_id=scan_id, scanner=INTERCEPTOR.value, status=status, settings={},
        ))
        await session.commit()
    return app_id, scan_id


def _rows(scan_id, host, auth_method) -> dict:
    """One https service on `host`, port 443, as the interceptor sees it: finish()'s results."""
    service_rows, url_rows = services_to_rows(scan_id, [{
        "scheme": "https", "host": host, "port": 443, "authentication": auth_method, "ips": None,
        "urls": [{"method": "GET", "url": f"https://{host}/", "status": 401, "authentication": auth_method}],
        "evidence_index": 0,
    }])
    for row in url_rows:
        row["scanner"] = INTERCEPTOR.value
    return {"service_rows": service_rows, "url_rows": url_rows}


async def _finish(factory, scan_id, host, auth_method) -> None:
    """End the scan's only job with one service on `host`, which finalizes the scan."""
    async with factory() as session:
        job = (await session.execute(select(ScanJobRow).where(ScanJobRow.scan_id == scan_id))).scalar_one()
        await finish(session, job.id, JobStatus.completed, pages_crawled=1, **_rows(scan_id, host, auth_method))
        await session.commit()


async def _scanned(factory, host, auth_method, *, app_id=None) -> tuple[str, str]:
    """A completed scan whose one service is `host`: (app id, scan id)."""
    app_id, scan_id = await _add_scan(factory, app_id=app_id)
    await _finish(factory, scan_id, host, auth_method)
    return app_id, scan_id


async def _service(factory, scan_id) -> ServiceRow:
    async with factory() as session:
        return (await session.execute(select(ServiceRow).where(ServiceRow.scan_id == scan_id))).scalar_one()


async def _events(factory, scan_id) -> list[tuple[str, dict]]:
    async with factory() as session:
        rows = await session.execute(
            select(ScanEventRow).where(ScanEventRow.scan_id == scan_id).order_by(ScanEventRow.seq)
        )
        return [(r.type, r.payload) for r in rows.scalars()]


async def _register(factory, host, scheme="https", port=443, note=""):
    body = CreatePublishedOriginRequest(scheme=scheme, host=host, port=port, note=note)
    return await create_published_origin(body, _request(factory))


async def _listed(factory, **query):
    return await list_published_origins(_request(factory), **query)


class TestRoutes:
    async def test_post_normalizes_the_origin_and_records_who(self, factory):
        entry = await _register(factory, "A.Example", scheme="HTTPS", note="vs_legacy")
        assert (entry.scheme, entry.host, entry.port, entry.note, entry.added_by) == (
            "https", "a.example", 443, "vs_legacy", "jchen",
        )
        assert entry.id.startswith("pub_") and entry.added_at
        assert (entry.removed_at, entry.removed_by) == (None, None)

    async def test_an_ipv6_host_loses_its_brackets(self, factory):
        # As urlparse().hostname, which the scanners key services on, stores it.
        entry = await _register(factory, "[::1]", port=8443)
        assert (entry.host, entry.port) == ("::1", 8443)

    @pytest.mark.parametrize("field, value", [
        ("scheme", "ftp"), ("host", ""), ("host", "  "), ("port", 0), ("port", 65536),
    ])
    def test_request_validation(self, field, value):
        fields = {"scheme": "https", "host": HOST, "port": 443, field: value}
        with pytest.raises(ValidationError):
            CreatePublishedOriginRequest(**fields)

    async def test_a_second_active_entry_for_an_origin_is_409(self, factory):
        await _register(factory, HOST)
        with pytest.raises(HTTPException) as e:
            await _register(factory, "A.EXAMPLE")
        assert e.value.status_code == 409

    async def test_delete_is_a_soft_delete_and_re_adding_is_a_new_entry(self, factory):
        first = await _register(factory, HOST)
        await delete_published_origin(first.id, _request(factory))
        assert await _listed(factory) == []
        [removed] = await _listed(factory, include_removed=True)
        assert (removed.id, removed.removed_by) == (first.id, "jchen") and removed.removed_at
        second = await _register(factory, HOST)
        assert second.id != first.id
        assert [e.id for e in await _listed(factory)] == [second.id]

    async def test_delete_of_an_unknown_or_removed_entry_is_404(self, factory):
        with pytest.raises(HTTPException) as e:
            await delete_published_origin("pub_nope", _request(factory))
        assert (e.value.status_code, e.value.detail["message"]) == (404, "published origin not found")
        entry = await _register(factory, HOST)
        await delete_published_origin(entry.id, _request(factory))
        with pytest.raises(HTTPException) as e:
            await delete_published_origin(entry.id, _request(factory))
        assert (e.value.status_code, e.value.detail["message"]) == (404, "published origin already removed")

    async def test_list_is_in_origin_order(self, factory):
        await _register(factory, "b.example")
        await _register(factory, "a.example", port=8443)
        await _register(factory, "a.example")
        assert [(e.host, e.port) for e in await _listed(factory)] == [
            ("a.example", 443), ("a.example", 8443), ("b.example", 443),
        ]


class TestVerdict:
    async def test_a_registered_origin_finishes_published(self, factory):
        entry = await _register(factory, HOST)
        _, scan_id = await _scanned(factory, HOST, "basic")
        row = await _service(factory, scan_id)
        assert (row.auth_method, row.severity, row.published_origin_id) == ("basic", "published", entry.id)
        # Nothing to report as a blocker: not an event, not in the summary, not at submit.
        events = await _events(factory, scan_id)
        assert [t for t, _ in events] == ["job_completed", "scan_completed"]
        assert events[-1][1]["blockers"] == 0
        assert (await get_scan(scan_id, _request(factory))).blocker_count == 0
        assert (await submit_scan(scan_id, _request(factory))).submission_id

    async def test_the_service_keeps_the_scanners_own_finding(self, factory):
        entry = await _register(factory, HOST)
        _, scan_id = await _scanned(factory, HOST, "basic")
        [service] = await list_services(scan_id, _request(factory))
        assert (service.severity, service.published_origin.id) == ("published", entry.id)
        assert [(f.scanner, f.auth_method, f.severity) for f in service.findings] == [
            ("interceptor", "basic", "blocker"),
        ]

    async def test_a_cleared_origin_is_published_too(self, factory):
        # The registry says what the origin is, whatever the scanners found.
        await _register(factory, HOST)
        _, scan_id = await _scanned(factory, HOST, "bearer")
        row = await _service(factory, scan_id)
        assert (row.auth_method, row.severity) == ("bearer", "published")

    async def test_registering_after_a_scan_completed_leaves_it_alone(self, factory):
        _, scan_id = await _scanned(factory, HOST, "basic")
        await _register(factory, HOST)
        row = await _service(factory, scan_id)
        assert (row.severity, row.published_origin_id) == ("blocker", None)

    async def test_a_removed_entry_does_not_publish_new_scans(self, factory):
        entry = await _register(factory, HOST)
        await delete_published_origin(entry.id, _request(factory))
        _, scan_id = await _scanned(factory, HOST, "basic")
        row = await _service(factory, scan_id)
        assert (row.severity, row.published_origin_id) == ("blocker", None)

    async def test_a_submitted_scan_keeps_pointing_at_a_removed_entry(self, factory):
        entry = await _register(factory, HOST)
        _, scan_id = await _scanned(factory, HOST, "basic")
        await submit_scan(scan_id, _request(factory))
        await delete_published_origin(entry.id, _request(factory))
        [service] = await list_services(scan_id, _request(factory))
        assert service.severity == "published"
        assert (service.published_origin.id, service.published_origin.removed_by) == (entry.id, "jchen")
        assert service.published_origin.removed_at

    async def test_a_fill_in_keeps_published(self, factory):
        entry = await _register(factory, HOST)
        _, scan_id = await _scanned(factory, HOST, "unknown")
        [service] = await list_services(scan_id, _request(factory))
        patched = await patch_service(
            scan_id, service.id, PatchServiceRequest(auth_method=AuthMethod.ntlm), _request(factory)
        )
        assert (patched.auth_method, patched.severity, patched.published_origin.id) == (
            "ntlm", "published", entry.id,
        )

    async def test_the_diff_lists_the_change(self, factory):
        app_id, before = await _scanned(factory, HOST, "basic")
        await _register(factory, HOST)
        _, after = await _scanned(factory, HOST, "basic", app_id=app_id)
        diff = await app_diff(app_id, _request(factory), from_=before, to=after)
        [service] = await list_services(after, _request(factory))
        assert diff.published_changes == [
            PublishedChange(id=service.id, scheme="https", host=HOST, port=443, before=False, after=True),
        ]
        assert (diff.auth_method_changes, diff.exclusion_changes, diff.added, diff.removed) == ([], [], [], [])
