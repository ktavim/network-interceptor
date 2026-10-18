"""End-to-end tests of the scan pipeline (crawl -> resolve -> probe -> report)
against the local fixture server. No database involved.

The fixture app references `*.example.com` hosts, which may or may not resolve
depending on the network the tests run on, so the first test asserts only
invariants that hold either way and the second pins the resolver."""

import logging
from urllib.parse import quote

import pytest

from config_tracer import pipeline
from config_tracer.extract import _classify_url
from config_tracer.models import AuthMethod, ConfigSource, Origin
from config_tracer.pipeline import _drop_hosts, _resolve_and_probe, run_scan
from config_tracer.report import ScanReport, build_report
from config_tracer.settings import ScanSettings

FAST = ScanSettings(nav_timeout_ms=10000, wait_after_load_ms=1000,
                    interact_budget_ms=1000, probe_timeout_s=3.0)


def _key(url: str) -> str:
    """The Origin.key of `url`: what ScanReport.service_map is indexed by."""
    return Origin.from_url(url).key


def _placed_urls(report: ScanReport) -> set[str]:
    return {u.url for svc in report.services for u in svc.urls}


@pytest.mark.asyncio
async def test_run_scan_places_every_clean_url(test_server):
    """Every clean URL the crawl extracts ends up under its service, whatever
    DNS says about the fixture's hostnames; a service on a host that failed DNS
    is dns_failed, down to each of its URLs."""
    report = await run_scan([test_server], FAST)

    assert isinstance(report, ScanReport)
    placed = _placed_urls(report)
    assert placed, "the crawl found nothing"
    assert all(_classify_url(u) is None for u in placed)
    # Provenance survives the pipeline: every placed URL names its sources.
    failed_by_host: dict[str, set[bool]] = {}
    for svc in report.services:
        failed = svc.auth_verdict is AuthMethod.DNS_FAILED
        failed_by_host.setdefault(svc.origin.host, set()).add(failed)
        assert failed == (svc.ips == [])
        if failed:
            assert svc.urls_probed == 0
        # The verdict's sample is one of the service's own URLs, carrying it.
        assert svc.url_map[svc.verdict_url].detected_method is svc.auth_verdict
        for evidence in svc.urls:
            assert Origin.from_url(evidence.url) == svc.origin
            assert evidence.sources
            if failed:
                assert evidence.detected_method is AuthMethod.DNS_FAILED
                assert evidence.error
                assert evidence.status_code is None  # never probed
    # DNS fails per host: a host's services all resolved or all failed.
    assert all(len(v) == 1 for v in failed_by_host.values())


@pytest.mark.asyncio
async def test_run_scan_probes_resolved_hosts(test_server, monkeypatch):
    """With every host resolving, each service is probed and every one of its
    URLs carries a verdict, with the transport error when it is no_response."""
    async def resolve_everything(hosts, timeout, max_concurrent):
        return [], {h: ["127.0.0.1"] for h in hosts}

    monkeypatch.setattr(pipeline, "resolve_hosts", resolve_everything)
    report = await run_scan([test_server], FAST)

    assert report.services
    for svc in report.services:
        assert svc.ips == ["127.0.0.1"]
        assert svc.urls_probed >= 1
        assert svc.urls
        assert svc.url_map[svc.verdict_url].detected_method is svc.auth_verdict
        for evidence in svc.urls:
            assert evidence.detected_method is not None
            assert ((evidence.detected_method is AuthMethod.NO_RESPONSE)
                    == (evidence.error is not None))


@pytest.mark.asyncio
async def test_run_scan_rejects_empty_seeds():
    with pytest.raises(ValueError):
        await run_scan([], ScanSettings())


@pytest.mark.asyncio
async def test_run_scan_logs_suspect_urls(monkeypatch, caplog):
    """A suspect URL is logged once, however many sources name it, with its
    reason and every source; it is never resolved or probed."""
    async def fake_crawl(seeds, **kwargs):
        return [
            ConfigSource(origin="js: https://app/a.js", urls_found=["https://${env}/x"]),
            ConfigSource(origin="js: https://app/b.js",
                         urls_found=["https://${env}/x", "http://[::1]:8080/y"]),
        ]

    async def no_dns(hosts, timeout, max_concurrent):
        raise AssertionError(f"resolved {hosts}")

    monkeypatch.setattr(pipeline, "crawl", fake_crawl)
    monkeypatch.setattr(pipeline, "resolve_hosts", no_dns)
    with caplog.at_level(logging.WARNING, logger="config_tracer.pipeline"):
        report = await run_scan(["https://app"], FAST)

    assert report.services == []
    assert [r.getMessage() for r in caplog.records] == [
        "Not probing suspect URL http://[::1]:8080/y (bad_host); found in js: https://app/b.js",
        "Not probing suspect URL https://${env}/x (template); "
        "found in js: https://app/a.js, js: https://app/b.js",
    ]


# ---------------------------------------------------------------------------
# Host roots and cross-origin redirect targets: the resolve/probe loop, without
# a browser.
#
# `auth_server` and `gated_auth_server` share 127.0.0.1 on two ports, so a
# redirect from one to the other is cross-origin by Origin while both
# resolve natively. Each test feeds its seeds through _resolve_and_probe and
# joins the result the way run_scan does, with the seeds as a `network:` source.
# ---------------------------------------------------------------------------

_BAD_HOST = "doesnotexist.invalid"


def _to(target: str) -> str:
    return quote(target, safe="")


async def _scan_seed(*seeds: str, settings: ScanSettings = FAST) -> ScanReport:
    auth_map, unresolved, ip_map, probe_srcs, sinkholed = await _resolve_and_probe(
        list(seeds), settings)
    sources = [ConfigSource(origin="network: seed", urls_found=list(seeds))] + probe_srcs
    kept, _ = _drop_hosts(sources, sinkholed)
    return build_report(kept, auth_map, unresolved, ip_map)


@pytest.mark.asyncio
async def test_synthesized_root_names_the_path_that_set_it_off(auth_server):
    """A 403 with no challenge sets off a probe of the host root, which is
    reported beside the path with `synthesized: <path>` as its provenance."""
    seed = f"{auth_server}/auth/forbidden"
    root = f"{auth_server}/"
    report = await _scan_seed(seed)

    svc = report.service_map[_key(seed)]
    assert [u.url for u in svc.urls] == [root, seed]
    assert svc.url_map[root].sources == [f"synthesized: {seed}"]
    assert svc.url_map[root].detected_method == AuthMethod.UNAUTHENTICATED
    assert svc.url_map[seed].sources == ["network: seed"]
    assert svc.url_map[seed].detected_method == AuthMethod.UNKNOWN


@pytest.mark.asyncio
async def test_root_synthesized_and_redirected_to_carries_both(auth_server, gated_auth_server):
    """A root one hop synthesizes and the next probes as a redirect target is
    listed once, with the target's own probe and both provenances in hop
    order."""
    root = f"{auth_server}/"
    forbidden = f"{auth_server}/auth/forbidden"
    redirector = f"{gated_auth_server}/auth/redirect-to?to={_to(root)}"
    report = await _scan_seed(forbidden, redirector)

    evidence = report.service_map[_key(root)].url_map[root]
    assert evidence.sources == [f"synthesized: {forbidden}", f"redirect: {redirector}"]
    assert evidence.detected_method == AuthMethod.UNAUTHENTICATED


@pytest.mark.asyncio
async def test_cross_origin_redirect_target_is_a_service(auth_server, gated_auth_server):
    """A 3xx whose Location is another origin surfaces that origin as a service
    with its own verdict and `redirect:` provenance, while the redirecting URL
    keeps its own verdict and the raw Location. The target is the gated root on
    purpose: every /auth/... path contains "auth", which _classify_redirect
    would read as a login redirect."""
    target = f"{gated_auth_server}/"
    seed = f"{auth_server}/auth/redirect-to?to={_to(target)}"
    report = await _scan_seed(seed)

    assert set(report.service_map) == {_key(seed), _key(target)}

    gated = report.service_map[_key(target)]
    assert gated.auth_verdict == AuthMethod.BASIC
    assert gated.urls_probed == 1
    evidence = gated.url_map[target]
    assert evidence.sources == [f"redirect: {seed}"]
    assert evidence.detected_method == AuthMethod.BASIC

    origin = report.service_map[_key(seed)]
    assert origin.auth_verdict == AuthMethod.UNKNOWN      # not the target's
    assert origin.url_map[seed].location == target
    assert origin.url_map[seed].sources == ["network: seed"]


@pytest.mark.asyncio
async def test_redirect_chain_is_followed_hop_by_hop(auth_server, gated_auth_server):
    """Each hop's targets are probed and may redirect again; a chain across
    origins places every URL once, each with the provenance of the URL that
    pointed at it."""
    last = f"{auth_server}/auth/none"
    middle = f"{gated_auth_server}/auth/redirect-to?to={_to(last)}"
    seed = f"{auth_server}/auth/redirect-to?to={_to(middle)}"
    report = await _scan_seed(seed)

    placed = {u.url: u for svc in report.services for u in svc.urls}
    assert set(placed) == {seed, middle, last}
    assert placed[middle].sources == [f"redirect: {seed}"]
    assert placed[last].sources == [f"redirect: {middle}"]
    assert placed[last].detected_method == AuthMethod.UNAUTHENTICATED
    assert sum(svc.urls_probed for svc in report.services) == 3


@pytest.mark.asyncio
async def test_cross_origin_redirect_loop_terminates(auth_server, gated_auth_server):
    """A loop across two origins closes on dedup: each URL is probed once and
    each carries the other as its redirect provenance."""
    seed = f"{auth_server}/auth/bounce?to={_to(gated_auth_server)}"
    peer = f"{gated_auth_server}/auth/bounce?to={_to(auth_server)}"
    report = await _scan_seed(seed)

    placed = {u.url: u for svc in report.services for u in svc.urls}
    assert set(placed) == {seed, peer}
    assert placed[seed].sources == ["network: seed", f"redirect: {peer}"]
    assert placed[peer].sources == [f"redirect: {seed}"]
    assert placed[seed].location == peer
    assert placed[peer].location == seed
    assert sum(svc.urls_probed for svc in report.services) == 2


@pytest.mark.asyncio
async def test_same_origin_redirect_adds_nothing(auth_server):
    """A redirect within one origin names a service already in the report."""
    seed = f"{auth_server}/auth/redirect"          # 301 -> /somewhere-else
    _, _, _, probe_srcs, _ = await _resolve_and_probe([seed], FAST)
    assert probe_srcs == []

    report = await _scan_seed(seed)
    assert set(report.service_map) == {_key(seed)}
    assert [u.url for u in report.services[0].urls] == [seed]


@pytest.mark.asyncio
async def test_unresolvable_redirect_target_is_reported(auth_server, monkeypatch):
    """A target whose host fails DNS is a finding on an internal estate: it is
    listed as a dns_failed service with its redirect provenance, never probed."""
    async def resolve_selectively(hosts, timeout, max_concurrent):
        failures = [{"host": h, "error": "NXDOMAIN"} for h in hosts if h == _BAD_HOST]
        return failures, {h: ["127.0.0.1"] for h in hosts if h != _BAD_HOST}

    monkeypatch.setattr(pipeline, "resolve_hosts", resolve_selectively)
    target = f"https://{_BAD_HOST}/api"
    seed = f"{auth_server}/auth/redirect-to?to={_to(target)}"
    report = await _scan_seed(seed)

    assert set(report.service_map) == {_key(seed), _key(target)}
    failed = report.service_map[_key(target)]
    assert failed.auth_verdict is AuthMethod.DNS_FAILED
    assert failed.ips == [] and failed.urls_probed == 0
    evidence = failed.url_map[target]
    assert evidence.sources == [f"redirect: {seed}"]
    assert evidence.detected_method is AuthMethod.DNS_FAILED
    assert evidence.error == "NXDOMAIN"
    assert evidence.status_code is None


@pytest.mark.asyncio
async def test_redirect_hops_are_capped(auth_server, gated_auth_server, monkeypatch, caplog):
    """Beyond the cap the chain is cut: the unfollowed target is dropped from
    the report entirely (not listed as a service that was never resolved) and
    the cut is logged. The redirecting URL still shows it in `location`."""
    monkeypatch.setattr(pipeline, "_MAX_REDIRECT_HOPS", 1)
    last = f"{auth_server}/auth/none"
    middle = f"{gated_auth_server}/auth/redirect-to?to={_to(last)}"
    seed = f"{auth_server}/auth/redirect-to?to={_to(middle)}"
    with caplog.at_level(logging.WARNING, logger="config_tracer.pipeline"):
        report = await _scan_seed(seed)

    placed = {u.url: u for svc in report.services for u in svc.urls}
    assert set(placed) == {seed, middle}
    assert placed[middle].location == last
    assert "1 target(s) not followed" in caplog.text


# ---------------------------------------------------------------------------
# DNS sinkhole: on a network whose DNS answers every unknown name with one
# placeholder address, a host resolving only to it is dropped, never probed.
# ---------------------------------------------------------------------------

_SINKHOLE = "10.255.255.1"
SINKHOLED = FAST.model_copy(update={"dns_sinkhole_ips": (_SINKHOLE,)})


def _fake_dns(answers: dict[str, list[str]]):
    async def resolve(hosts, timeout, max_concurrent):
        return [], {h: answers.get(h, ["127.0.0.1"]) for h in hosts}
    return resolve


@pytest.mark.asyncio
async def test_run_scan_drops_sinkholed_hosts(auth_server, monkeypatch, caplog):
    """URLs on a host resolving only to the sinkhole are dropped from JS and
    JSON sources alike, are never probed, and are logged. A host with a real
    address beside the placeholder is kept and probed."""
    port = auth_server.rsplit(":", 1)[1]
    internal = f"{auth_server}/auth/none"
    mixed = f"http://mixed.test:{port}/auth/none"
    cdn = "https://cdn.public.test/lib.js"
    api = "https://api.public.test/v1"

    async def fake_crawl(seeds, **kwargs):
        return [
            ConfigSource(origin="js: https://app/main.js", urls_found=[internal, cdn]),
            ConfigSource(origin="json: https://app/config.json", urls_found=[api, cdn]),
            ConfigSource(origin="json: https://app/env.json", urls_found=[mixed]),
        ]

    probed: list[str] = []
    real_probe = pipeline.probe_urls_with_roots

    async def recording_probe(urls, **kwargs):
        probed.extend(urls)
        return await real_probe(urls, **kwargs)

    monkeypatch.setattr(pipeline, "crawl", fake_crawl)
    monkeypatch.setattr(pipeline, "resolve_hosts", _fake_dns({
        "cdn.public.test": [_SINKHOLE],
        "api.public.test": [_SINKHOLE],
        "mixed.test": ["127.0.0.1", _SINKHOLE],
    }))
    monkeypatch.setattr(pipeline, "probe_urls_with_roots", recording_probe)
    with caplog.at_level(logging.DEBUG, logger="config_tracer.pipeline"):
        report = await run_scan(["https://app"], SINKHOLED)

    assert sorted(probed) == sorted([internal, mixed])
    assert _placed_urls(report) == {internal, mixed}
    assert report.service_map[_key(mixed)].ips == ["127.0.0.1", _SINKHOLE]
    messages = [r.getMessage() for r in caplog.records]
    assert ("Dropped 2 URL(s) on 2 host(s) resolving only to the DNS sinkhole: "
            "api.public.test, cdn.public.test") in messages
    assert (f"Dropped sinkholed URL {cdn}; found in "
            "js: https://app/main.js, json: https://app/config.json") in messages


@pytest.mark.asyncio
async def test_sinkholed_host_kept_without_sinkhole_configured(monkeypatch):
    """With no sinkhole configured, the placeholder is an address like any
    other: the host is a service and is probed."""
    target = "https://cdn.public.test/lib.js"
    monkeypatch.setattr(pipeline, "resolve_hosts",
                        _fake_dns({"cdn.public.test": [_SINKHOLE]}))
    report = await _scan_seed(target)

    svc = report.service_map[_key(target)]
    assert svc.ips == [_SINKHOLE]
    assert svc.urls_probed == 1


@pytest.mark.asyncio
async def test_sinkholed_redirect_target_is_dropped(auth_server, monkeypatch):
    """A redirect target on a sinkholed host is not a service; the redirecting
    URL keeps its own verdict and the target in `location`."""
    monkeypatch.setattr(pipeline, "resolve_hosts",
                        _fake_dns({"login.public.test": [_SINKHOLE]}))
    target = "https://login.public.test/authorize"
    seed = f"{auth_server}/auth/redirect-to?to={_to(target)}"
    report = await _scan_seed(seed, settings=SINKHOLED)

    assert set(report.service_map) == {_key(seed)}
    evidence = report.service_map[_key(seed)].url_map[seed]
    assert evidence.location == target
    assert evidence.sources == ["network: seed"]
