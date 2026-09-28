"""The manual auth-method override in PATCH /scans/{id}/services/{id}, against a
real Postgres. Set TEST_DATABASE_URL to run."""
import os
import uuid
from types import SimpleNamespace

import pytest
from dotenv import dotenv_values
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api.models import PatchServiceRequest
from api.routes_scans import patch_service
from core.db import AppRow, Base, ScanRow, ServiceRow
from core.enums import AuthMethod, Severity

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")
DEV_DATABASE_URL = os.environ.get("DATABASE_URL") or dotenv_values().get("DATABASE_URL")

pytestmark = [
    pytest.mark.skipif(not TEST_DATABASE_URL, reason="TEST_DATABASE_URL not set"),
    # The fixture truncates every table.
    pytest.mark.skipif(
        TEST_DATABASE_URL is not None and TEST_DATABASE_URL == DEV_DATABASE_URL,
        reason="TEST_DATABASE_URL is DATABASE_URL",
    ),
]


@pytest.fixture
async def factory():
    engine = create_async_engine(TEST_DATABASE_URL)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("TRUNCATE apps, scans, scan_events, services, urls, submissions CASCADE"))
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


async def _add_service(factory, auth_method: AuthMethod, severity: Severity) -> tuple:
    """A service on an app's only completed scan, so it is editable."""
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
            auth_method=auth_method.value, severity=severity.value,
        ))
        await session.commit()
    return scan_id, service_id


async def _patch(factory, scan_id, service_id, auth_method: AuthMethod):
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(session_factory=factory)))
    return await patch_service(scan_id, service_id, PatchServiceRequest(auth_method=auth_method), request)


@pytest.mark.parametrize("fill_in", [AuthMethod.unknown, AuthMethod.no_response])
async def test_fill_in_methods_can_be_set_and_severity_follows(factory, fill_in):
    scan_id, service_id = await _add_service(factory, fill_in, Severity.review)
    service = await _patch(factory, scan_id, service_id, AuthMethod.ntlm)
    assert (service.auth_method, service.severity) == ("ntlm", "blocker")


@pytest.mark.parametrize("target", [AuthMethod.unknown, AuthMethod.no_response])
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
