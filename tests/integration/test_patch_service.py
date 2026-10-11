"""The manual auth-method override in PATCH /scans/{id}/services/{id}, against a
real Postgres. Set TEST_DATABASE_URL to run."""
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from api.models import PatchServiceRequest
from api.routes_scans import patch_service
from core.db import AppRow, PublishedOriginRow, ScanRow, ServiceRow
from core.enums import AuthMethod, Severity


async def _add_service(factory, auth_method: AuthMethod, severity: Severity, **fields) -> tuple:
    """A service on an app's only completed scan, so it is editable. `fields`
    are further columns of the service row."""
    app_id, scan_id, service_id = uuid.uuid4().hex, uuid.uuid4().hex, uuid.uuid4().hex
    async with factory() as session:
        session.add(AppRow(id=app_id, name="app", url="http://x", owner_ad_group="g"))
        session.add(ScanRow(
            id=scan_id, app_id=app_id, name="app", url="http://x",
            status="completed", started_by="test",
        ))
        await session.flush()
        session.add(ServiceRow(
            id=service_id, scan_id=scan_id, scheme="https", host="a.com", port=443,
            auth_method=auth_method.value, severity=severity.value, **fields,
        ))
        await session.commit()
    return scan_id, service_id


async def _patch(factory, scan_id, service_id, auth_method: AuthMethod):
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(session_factory=factory)))
    return await patch_service(scan_id, service_id, PatchServiceRequest(auth_method=auth_method), request)


_FILL_INS = [AuthMethod.unknown, AuthMethod.no_response, AuthMethod.dns_failed]


@pytest.mark.parametrize("fill_in", _FILL_INS)
async def test_fill_in_methods_can_be_set_and_severity_follows(factory, fill_in):
    scan_id, service_id = await _add_service(factory, fill_in, Severity.review)
    service = await _patch(factory, scan_id, service_id, AuthMethod.ntlm)
    assert (service.auth_method, service.severity) == ("ntlm", "blocker")


@pytest.mark.parametrize("target", _FILL_INS)
async def test_cannot_set_a_fill_in_method(factory, target):
    # Only the crawler says it could not tell; a person fills in what it is.
    scan_id, service_id = await _add_service(factory, AuthMethod.no_response, Severity.review)
    with pytest.raises(HTTPException) as e:
        await _patch(factory, scan_id, service_id, target)
    assert e.value.status_code == 422


async def test_detected_method_stays_locked(factory):
    scan_id, service_id = await _add_service(factory, AuthMethod.unauthenticated, Severity.cleared)
    with pytest.raises(HTTPException) as e:
        await _patch(factory, scan_id, service_id, AuthMethod.ntlm)
    assert e.value.status_code == 409


async def test_a_published_service_keeps_its_severity_when_filled_in(factory):
    # The registry's verdict stands whatever the label says; only the label changes.
    entry_id = "pub_" + uuid.uuid4().hex[:10]
    async with factory() as session:
        session.add(PublishedOriginRow(
            id=entry_id, scheme="https", host="a.com", port=443, note="", added_by="test",
        ))
        await session.commit()
    scan_id, service_id = await _add_service(
        factory, AuthMethod.unknown, Severity.published, published_origin_id=entry_id
    )
    service = await _patch(factory, scan_id, service_id, AuthMethod.ntlm)
    assert (service.auth_method, service.severity, service.published_origin.id) == (
        "ntlm", "published", entry_id,
    )
