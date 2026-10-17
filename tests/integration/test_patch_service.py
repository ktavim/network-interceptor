"""The manual auth-method override in PATCH /scans/{id}/services/{id}, against a
real Postgres. Set TEST_DATABASE_URL to run."""
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from api.models import PatchServiceRequest
from api.routes_scans import patch_service
from core.db import AppRow, PublishedOriginRow, ScanRow, ServiceFindingRow, ServiceRow
from core.enums import AuthMethod, Scanner, Severity


async def _add_service(
    factory, auth_method: AuthMethod, severity: Severity, *, tracer: AuthMethod | None = None, **fields
) -> tuple:
    """A service on an app's only completed scan, so it is editable. The
    interceptor found it `auth_method`; with `tracer`, the tracer found it too,
    and the service is labelled `auth_method` regardless. `fields` are further
    columns of the service row."""
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
        await session.flush()
        found = [(Scanner.interceptor, auth_method)] + ([(Scanner.tracer, tracer)] if tracer else [])
        session.add_all(
            ServiceFindingRow(service_id=service_id, scanner=scanner.value, auth_method=method.value, url_count=1)
            for scanner, method in found
        )
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
    assert (service.auth_method, service.scanners_auth_method, service.severity) == (
        "ntlm", fill_in.value, "blocker",
    )


@pytest.mark.parametrize("verdict, target", [
    # Not the verdict itself: setting that is an undo.
    (verdict, target) for verdict in _FILL_INS for target in _FILL_INS if target is not verdict
])
async def test_cannot_set_another_fill_in_method(factory, verdict, target):
    # Only the scanners say they could not tell; a person fills in what it is.
    scan_id, service_id = await _add_service(factory, verdict, Severity.review)
    with pytest.raises(HTTPException) as e:
        await _patch(factory, scan_id, service_id, target)
    assert e.value.status_code == 422


@pytest.mark.parametrize("mechanism, severity", [
    (AuthMethod.kerberos, "cleared"), (AuthMethod.ntlm, "blocker"),
])
async def test_negotiate_can_be_named_as_its_mechanism(factory, mechanism, severity):
    scan_id, service_id = await _add_service(factory, AuthMethod.negotiate, Severity.review)
    service = await _patch(factory, scan_id, service_id, mechanism)
    assert (service.auth_method, service.severity) == (mechanism.value, severity)


@pytest.mark.parametrize("target", [AuthMethod.bearer, AuthMethod.unauthenticated, AuthMethod.unknown])
async def test_negotiate_cannot_be_set_to_anything_but_a_mechanism(factory, target):
    scan_id, service_id = await _add_service(factory, AuthMethod.negotiate, Severity.review)
    with pytest.raises(HTTPException) as e:
        await _patch(factory, scan_id, service_id, target)
    assert e.value.status_code == 422


@pytest.mark.parametrize("verdict, first, second", [
    (AuthMethod.unknown, AuthMethod.ntlm, AuthMethod.bearer),
    (AuthMethod.negotiate, AuthMethod.kerberos, AuthMethod.ntlm),
])
async def test_a_correction_can_be_corrected(factory, verdict, first, second):
    scan_id, service_id = await _add_service(factory, verdict, Severity.review)
    await _patch(factory, scan_id, service_id, first)
    service = await _patch(factory, scan_id, service_id, second)
    assert (service.auth_method, service.scanners_auth_method) == (second.value, verdict.value)


@pytest.mark.parametrize("verdict, correction", [
    (AuthMethod.no_response, AuthMethod.ntlm),
    (AuthMethod.negotiate, AuthMethod.kerberos),
])
async def test_setting_the_verdict_back_undoes_a_correction(factory, verdict, correction):
    scan_id, service_id = await _add_service(factory, verdict, Severity.review)
    await _patch(factory, scan_id, service_id, correction)
    service = await _patch(factory, scan_id, service_id, verdict)
    assert (service.auth_method, service.severity) == (verdict.value, "review")


async def test_a_correction_cannot_reach_beyond_the_verdicts_targets(factory):
    # Once named kerberos, a negotiate service is still bounded by negotiate's targets.
    scan_id, service_id = await _add_service(factory, AuthMethod.negotiate, Severity.review)
    await _patch(factory, scan_id, service_id, AuthMethod.kerberos)
    with pytest.raises(HTTPException) as e:
        await _patch(factory, scan_id, service_id, AuthMethod.bearer)
    assert e.value.status_code == 422


async def test_detected_method_stays_locked(factory):
    scan_id, service_id = await _add_service(factory, AuthMethod.unauthenticated, Severity.cleared)
    with pytest.raises(HTTPException) as e:
        await _patch(factory, scan_id, service_id, AuthMethod.ntlm)
    assert e.value.status_code == 409


async def test_a_negotiate_the_other_scanner_resolved_stays_locked(factory):
    # The merge already named the mechanism (core.merge._pick), so nothing is left to fill in.
    scan_id, service_id = await _add_service(
        factory, AuthMethod.negotiate, Severity.review, tracer=AuthMethod.kerberos
    )
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
