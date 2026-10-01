"""A scan with only a tracer worker running: the real tracer engine against
config-tracer's fixture servers, from POST /scans through the queue and the
tracer runner into a real Postgres, read back through the API's routes.

The interceptor job stays queued throughout, so the scan's services are the
tracer's alone, and they are the ones config-tracer's own tests expect of
these servers. Set TEST_DATABASE_URL to run.
"""
import asyncio
import uuid
from types import SimpleNamespace
from urllib.parse import quote

from sqlalchemy import select

from api.models import CreateScanRequest
from api.routes_scans import create_scan, get_scan, list_service_urls, list_services
from config_tracer import pipeline
from config_tracer.models import ConfigSource
from config_tracer.settings import ScanSettings
from core.db import AppRow, ScanJobRow, ServiceFindingRow, UrlRow
from core.enums import Scanner
from core.jobs import claim_next
from tests.tracer.conftest import auth_server, gated_auth_server, test_server  # noqa: F401
from worker.job import Job, run_tracer_job

# As config-tracer's crawl tests run it, with the budget its click test needs.
SETTINGS = ScanSettings(
    nav_timeout_ms=10000, wait_after_load_ms=2000, interact_budget_ms=6000, probe_timeout_s=3.0
)


def _request(factory) -> SimpleNamespace:
    state = SimpleNamespace(session_factory=factory, tracer_settings=SETTINGS)
    return SimpleNamespace(app=SimpleNamespace(state=state))


async def _scan_with_a_tracer_worker(factory, url: str) -> str:
    """Request a scan of an app at `url`, then do what a tracer worker would:
    claim the scan's tracer job and run it. Returns the scan id."""
    app_id = uuid.uuid4().hex
    async with factory() as session:
        session.add(AppRow(id=app_id, name="app", url=url, owner_ad_group="g"))
        await session.commit()
    scan_id = (await create_scan(CreateScanRequest(app_id=app_id), _request(factory))).scan_id
    job = Job(await claim_next(factory, Scanner.tracer, "tracer-worker"))
    job.task = asyncio.create_task(run_tracer_job(job, factory, timeout_s=120))
    await job.task
    return scan_id


async def _job_statuses(factory, scan_id) -> dict:
    async with factory() as session:
        rows = await session.execute(
            select(ScanJobRow.scanner, ScanJobRow.status, ScanJobRow.error).where(ScanJobRow.scan_id == scan_id)
        )
        return {scanner: (status, error) for scanner, status, error in rows}


async def _services(factory, scan_id) -> dict:
    """The scan's services as GET /scans/{id}/services lists them, by host and port."""
    return {(s.host, s.port): s for s in await list_services(scan_id, _request(factory))}


async def _urls(factory, scan_id, service) -> dict:
    """The service's urls as GET .../services/{id}/urls lists them, by url."""
    return {u.url: u for u in await list_service_urls(scan_id, service.id, _request(factory))}


async def _sources(factory, service_id) -> dict:
    """{url: (scanner, sources)} of a service's url rows; the API does not show these yet."""
    async with factory() as session:
        rows = (await session.execute(select(UrlRow).where(UrlRow.service_id == service_id))).scalars()
        return {row.url: (row.scanner, row.sources) for row in rows}


async def _finding_scanners(factory, service_id) -> list:
    async with factory() as session:
        return (await session.execute(
            select(ServiceFindingRow.scanner).where(ServiceFindingRow.service_id == service_id)
        )).scalars().all()


async def test_scan_of_the_config_fixture_finds_the_services_its_configs_name(factory, test_server, monkeypatch):  # noqa: F811
    # The fixture app names *.example.com hosts. Whether those resolve depends on
    # the network the tests run on, so the resolver is pinned to refuse them.
    async def resolve_nothing(hosts, timeout, max_concurrent):
        return [{"host": h, "error": "NXDOMAIN"} for h in sorted(hosts)], {}

    monkeypatch.setattr(pipeline, "resolve_hosts", resolve_nothing)

    scan_id = await _scan_with_a_tracer_worker(factory, test_server)

    assert await _job_statuses(factory, scan_id) == {"tracer": ("completed", None), "interceptor": ("queued", None)}
    assert (await get_scan(scan_id, _request(factory))).status == "running"
    # The URL each crawl strategy of config-tracer's tests finds, and where it was found.
    expected = {
        "strategy-a.example.com": ("https://strategy-a.example.com/api", 'dom: <script type="application/json">'),
        "strategy-b.example.com": ("https://strategy-b.example.com/cdn", "dom: inline script (window.__CONFIG__)"),
        "network.example.com": ("https://network.example.com/dashboard", f"network: {test_server}/api/settings.json"),
        "click-triggered.example.com": (
            "https://click-triggered.example.com/api", f"network: {test_server}/api/click-only.json"),
        "chunk-admin.example.com": (
            "https://chunk-admin.example.com/api", f"js: {test_server}/static/js/chunk-admin.js"),
    }
    services = await _services(factory, scan_id)
    # Not deep-page.example.com: the default scan visits one page and follows no links.
    assert set(services) == {(host, 443) for host in expected}
    for (host, _), service in services.items():
        url, source = expected[host]
        # A host that failed DNS is a service all the same: review, and no addresses.
        assert (service.scheme, service.auth_method, service.severity) == ("https", "dns_failed", "review")
        assert (service.request_count, service.ips, service.excluded) == (1, None, False)
        [listed] = (await _urls(factory, scan_id, service)).values()
        assert service.evidence == listed
        assert (listed.url, listed.method, listed.resource_type) == (url, "", "probe")
        assert (listed.status_code, listed.failure_reason, listed.auth_method) == (0, "NXDOMAIN", "dns_failed")
        assert await _sources(factory, service.id) == {url: ("tracer", [source])}
        assert await _finding_scanners(factory, service.id) == ["tracer"]


async def test_scan_of_the_auth_fixture_gives_each_origin_its_probed_verdict(
    factory, auth_server, gated_auth_server, monkeypatch,  # noqa: F811
):
    # The auth fixture's paths are probe targets that no page of it names, so the
    # crawl is stood in for by a config naming them. Resolving and probing are real.
    gated_root = f"{gated_auth_server}/"
    named = [
        f"{auth_server}/auth/bearer",
        f"{auth_server}/auth/none",
        f"{auth_server}/auth/forbidden",
        f"{auth_server}/auth/redirect-login",
        f"{auth_server}/auth/redirect-to?to={quote(gated_root, safe='')}",
    ]
    config = f"network: {auth_server}/config.json"

    async def crawl(seeds, **kwargs):
        return [ConfigSource(origin=config, urls_found=named)]

    monkeypatch.setattr(pipeline, "crawl", crawl)

    scan_id = await _scan_with_a_tracer_worker(factory, auth_server)

    assert await _job_statuses(factory, scan_id) == {"tracer": ("completed", None), "interceptor": ("queued", None)}
    services = await _services(factory, scan_id)
    app_port, gated_port = (int(server.rsplit(":", 1)[1]) for server in (auth_server, gated_auth_server))
    assert set(services) == {("127.0.0.1", app_port), ("127.0.0.1", gated_port)}

    # The origin the config names: its worst URL is the Bearer challenge.
    app = services["127.0.0.1", app_port]
    assert (app.scheme, app.auth_method, app.severity) == ("http", "bearer", "cleared")
    assert (app.request_count, app.ips) == (6, ["127.0.0.1"])
    assert (app.evidence.url, app.evidence.auth_challenge) == (f"{auth_server}/auth/bearer", "Bearer")
    urls = await _urls(factory, scan_id, app)
    assert {url: (u.method, u.status_code, u.auth_method, u.redirect_url) for url, u in urls.items()} == {
        # Probed on the tracer's own initiative, after the 403 that named no scheme.
        f"{auth_server}/": ("HEAD", 200, "unauthenticated", None),
        f"{auth_server}/auth/bearer": ("HEAD", 401, "bearer", None),
        f"{auth_server}/auth/none": ("HEAD", 200, "unauthenticated", None),
        f"{auth_server}/auth/forbidden": ("HEAD", 403, "unknown", None),
        # The relative Location, resolved, and its query string dropped.
        f"{auth_server}/auth/redirect-login": ("HEAD", 302, "login_redirect", f"{auth_server}/oauth/authorize"),
        # The probed URL has lost its query string too.
        f"{auth_server}/auth/redirect-to": ("HEAD", 302, "unknown", gated_root),
    }
    assert all((u.resource_type, u.page_url, u.failure_reason) == ("probe", "", None) for u in urls.values())
    sources = await _sources(factory, app.id)
    assert sources.pop(f"{auth_server}/") == ("tracer", [f"synthesized: {auth_server}/auth/forbidden"])
    assert len(sources) == 5 and all(found == ("tracer", [config]) for found in sources.values())

    # The origin the redirect disclosed: a service of its own, with its own verdict.
    gated = services["127.0.0.1", gated_port]
    assert (gated.scheme, gated.auth_method, gated.severity) == ("http", "basic", "blocker")
    assert (gated.request_count, gated.ips) == (1, ["127.0.0.1"])
    [root] = (await _urls(factory, scan_id, gated)).values()
    assert gated.evidence == root
    assert (root.url, root.method, root.status_code) == (gated_root, "HEAD", 401)
    assert (root.auth_method, root.auth_challenge) == ("basic", 'Basic realm="gated"')
    assert await _sources(factory, gated.id) == {
        gated_root: ("tracer", [f"redirect: {auth_server}/auth/redirect-to"]),
    }
