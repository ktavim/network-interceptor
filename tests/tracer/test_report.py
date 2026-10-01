"""Tests for config_tracer.report.build_report — the pure join of extraction,
DNS, and probe results into a ScanReport. Each test pins one semantic of the
report the persistence layer and API depend on."""

from config_tracer.extract import _classify_url
from config_tracer.models import (
    AuthInfo, AuthMethod, ConfigSource, HttpMethod, Origin, ProbeResult,
)
from config_tracer.report import (
    ScanReport,
    UrlEvidence,
    build_report,
)


def _auth_info(url, method, *, status=200, error=None, http_method=HttpMethod.HEAD):
    return AuthInfo(
        url=url,
        probe_result=ProbeResult(
            url=url, http_method=http_method, status_code=status,
            www_authenticate=None, detected_method=method, error=error,
        ),
    )


def test_report_quarantines_suspect_urls():
    sources = [ConfigSource(
        origin="js: https://test/bundle.js",
        urls_found=[
            "https://real.example.com/api",
            "https://${env}/x",
            "https://www.%/y",
        ],
    )]
    report = build_report(sources)

    # The clean URL survives into the services list — the only place URLs are
    # reported — carrying the origin it was extracted from.
    svc = report.service_map["https://real.example.com"]
    assert svc.url_map == {
        "https://real.example.com/api": UrlEvidence(
            url="https://real.example.com/api",
            sources=["js: https://test/bundle.js"])}
    assert {s.url for s in report.suspect_urls} == {
        "https://${env}/x", "https://www.%/y",
    }
    reasons = {s.url: s.reason for s in report.suspect_urls}
    assert reasons["https://${env}/x"] == "template"
    assert reasons["https://www.%/y"] == "bad_host"
    for s in report.suspect_urls:
        assert s.sources == ["js: https://test/bundle.js"]


def test_report_services_collapse_and_filter():
    """Services collapse each service's per-URL verdicts by precedence
    (concrete scheme > none), keeping each URL's own, and collapse a
    service whose every probe failed to `no_response`. A host that failed DNS
    is a service too, `dns_failed`. Keys are origins; `ips` are joined through
    the host."""
    sources = [ConfigSource(
        origin="js: https://app/bundle.js",
        urls_found=[
            "https://svc.example.com/api",   # bearer
            "https://svc.example.com/",      # unauthenticated -> URLs disagree
            "https://down.example.com/x",    # resolved but probe failed
            "https://dead.example.com/y",    # failed DNS -> dns_failed
        ],
    )]
    auth_map = {
        "https://svc.example.com/api": _auth_info(
            "https://svc.example.com/api", AuthMethod.BEARER, status=401,
            http_method=HttpMethod.GET),
        "https://svc.example.com/": _auth_info(
            "https://svc.example.com/", AuthMethod.UNAUTHENTICATED),
        "https://down.example.com/x": _auth_info(
            "https://down.example.com/x", AuthMethod.NO_RESPONSE, status=None,
            error="Cannot connect to host"),
    }
    unresolved = [{"host": "dead.example.com", "error": "NXDOMAIN"}]
    ip_map = {
        "svc.example.com": ["10.0.0.5"],
        "down.example.com": ["10.0.0.6", "10.0.0.7"],  # multiple A records
    }

    report = build_report(sources, auth_map, unresolved, ip_map)

    services = report.service_map
    assert set(services) == {
        "https://svc.example.com", "https://down.example.com", "https://dead.example.com"}
    assert services["https://dead.example.com"].auth_verdict is AuthMethod.DNS_FAILED
    assert services["https://dead.example.com"].verdict_url == "https://dead.example.com/y"

    svc = services["https://svc.example.com"]
    assert svc.origin == Origin("https", "svc.example.com", 443)
    assert svc.ips == ["10.0.0.5"]  # joined through the host
    assert svc.auth_verdict is AuthMethod.BEARER  # concrete scheme outranks none
    assert svc.verdict_url == "https://svc.example.com/api"  # not the open root
    # The evidence the scalars above were collapsed from: each URL's own verdict,
    # and the request and status it was read off.
    assert svc.url_map == {
        "https://svc.example.com/": UrlEvidence(
            url="https://svc.example.com/", http_method=HttpMethod.HEAD, status_code=200,
            detected_method=AuthMethod.UNAUTHENTICATED,
            sources=["js: https://app/bundle.js"]),
        "https://svc.example.com/api": UrlEvidence(
            url="https://svc.example.com/api", http_method=HttpMethod.GET, status_code=401,
            detected_method=AuthMethod.BEARER,
            sources=["js: https://app/bundle.js"]),
    }
    assert svc.urls_probed == 2

    down = services["https://down.example.com"]
    assert down.ips == ["10.0.0.6", "10.0.0.7"]  # multiple IPs preserved
    assert down.auth_verdict is AuthMethod.NO_RESPONSE  # only a transport error
    assert down.verdict_url == "https://down.example.com/x"
    # The error string survives the collapse — the verdict alone would not say
    # whether this host refused the connection, timed out, or failed TLS.
    assert down.url_map == {
        "https://down.example.com/x": UrlEvidence(
            url="https://down.example.com/x", http_method=HttpMethod.HEAD,
            detected_method=AuthMethod.NO_RESPONSE, error="Cannot connect to host",
            sources=["js: https://app/bundle.js"]),
    }
    assert down.urls_probed == 1


def test_report_failed_probe_is_not_masked_by_an_open_sibling():
    """A URL that gave no response is one whose demands we don't know, so an
    open sibling must not headline the service as `unauthenticated`: the
    failure takes part in the collapse, and the open URL keeps its own verdict."""
    sources = [ConfigSource(
        origin="js: https://app/bundle.js",
        urls_found=["https://svc.example.com/", "https://svc.example.com/api"],
    )]
    auth_map = {
        "https://svc.example.com/": _auth_info(
            "https://svc.example.com/", AuthMethod.UNAUTHENTICATED),
        "https://svc.example.com/api": _auth_info(
            "https://svc.example.com/api", AuthMethod.NO_RESPONSE, status=None,
            error="timeout"),
    }

    svc = build_report(sources, auth_map, [], {}).service_map["https://svc.example.com"]

    assert svc.auth_verdict is AuthMethod.NO_RESPONSE
    assert svc.url_map["https://svc.example.com/"].detected_method is AuthMethod.UNAUTHENTICATED
    assert svc.urls_probed == 2


def test_report_verdict_url_samples_the_verdict():
    """verdict_url is a URL whose own verdict is the service's, passing over one
    that sorts before it with another verdict. Among several it is the first in
    code-point order, where upper case sorts before lower whatever a database
    collation would say, so the migration's backfill agrees with it."""
    root, lower, upper = ("https://svc.example.com/", "https://svc.example.com/a-admin",
                          "https://svc.example.com/B-admin")
    sources = [ConfigSource(origin="js: https://app/bundle.js", urls_found=[root, lower, upper])]
    auth_map = {
        root: _auth_info(root, AuthMethod.UNAUTHENTICATED),
        lower: _auth_info(lower, AuthMethod.NTLM, status=401),
        upper: _auth_info(upper, AuthMethod.NTLM, status=401),
    }

    svc = build_report(sources, auth_map, [], {}).service_map["https://svc.example.com"]

    assert svc.auth_verdict is AuthMethod.NTLM
    assert svc.verdict_url == upper


def test_report_services_listed_when_nothing_probed():
    """With no DNS or probe results, a service is still listed: services are
    the only place a clean URL is reported, so gating them on the later passes
    would drop the extraction itself. The entry is honestly empty-handed: no
    ips, a None verdict, nothing probed."""
    sources = [ConfigSource(
        origin="js: https://app/bundle.js",
        urls_found=["https://svc.example.com/api"],
    )]
    report = build_report(sources)

    svc = report.service_map["https://svc.example.com"]
    assert svc.url_map == {
        "https://svc.example.com/api": UrlEvidence(
            url="https://svc.example.com/api",
            sources=["js: https://app/bundle.js"])}
    assert svc.ips == []
    assert svc.auth_verdict is None
    assert svc.verdict_url is None  # not the unprobed URL, whose method is None too
    assert svc.urls_probed == 0


def test_report_keys_services_by_origin():
    """Two ports on one host are distinct services; http vs https are distinct;
    the scheme's default port collapses into the bare origin, stored as the
    effective port; and `ips` are shared across services on the same host."""
    sources = [ConfigSource(
        origin="js: https://app/bundle.js",
        urls_found=[
            "https://svc.example.com/api",        # https default (:443)
            "https://svc.example.com:443/admin",  # same service as above
            "https://svc.example.com:8080/x",     # distinct: non-default port
            "http://svc.example.com/y",            # distinct: different scheme
        ],
    )]
    auth_map = {
        "https://svc.example.com/api": _auth_info(
            "https://svc.example.com/api", AuthMethod.NEGOTIATE, status=401),
        "https://svc.example.com:443/admin": _auth_info(
            "https://svc.example.com:443/admin", AuthMethod.NEGOTIATE, status=401),
        "https://svc.example.com:8080/x": _auth_info(
            "https://svc.example.com:8080/x", AuthMethod.UNAUTHENTICATED),
        "http://svc.example.com/y": _auth_info(
            "http://svc.example.com/y", AuthMethod.BASIC, status=401),
    }
    ip_map = {"svc.example.com": ["10.0.0.5"]}

    report = build_report(sources, auth_map, [], ip_map)

    services = report.service_map
    assert set(services) == {
        "https://svc.example.com",        # :443 folded in with the default
        "https://svc.example.com:8080",
        "http://svc.example.com",
    }
    # Sorted by host, then port, then scheme: one box's services together.
    assert [s.origin for s in report.services] == [
        Origin("http", "svc.example.com", 80),
        Origin("https", "svc.example.com", 443),
        Origin("https", "svc.example.com", 8080),
    ]
    # The :443 URL collapsed into the bare https origin, not its own row, and
    # the origin carries 443 explicitly rather than "no port".
    https_default = services["https://svc.example.com"]
    assert https_default.origin.port == 443
    assert https_default.urls_probed == 2
    assert https_default.auth_verdict is AuthMethod.NEGOTIATE
    # Distinct port and distinct scheme keep their own verdicts.
    assert services["https://svc.example.com:8080"].auth_verdict is AuthMethod.UNAUTHENTICATED
    assert services["http://svc.example.com"].auth_verdict is AuthMethod.BASIC
    # All three share the one host's resolved IPs.
    assert all(s.ips == ["10.0.0.5"] for s in report.services)


def test_report_services_list_their_urls():
    """Each service carries `urls`: every clean discovered URL on that origin,
    sorted. Origin-scoped like the rest of the entry, so a second port on the
    same box gets its own list rather than sharing one."""
    sources = [
        ConfigSource(
            origin="js: https://app/bundle.js",
            urls_found=[
                "https://svc.example.com/z-api",
                "https://svc.example.com:8443/admin",   # distinct service
                "https://dead.example.com/gone",        # failed DNS -> own service
                "https://svc.example.com/${env}/tpl",   # suspect -> not a URL
            ],
        ),
        ConfigSource(  # a second source referencing one of the same URLs
            origin="network: https://svc.example.com/config.json",
            urls_found=[
                "https://svc.example.com/a-api",
                "https://svc.example.com/z-api",
            ],
        ),
    ]
    auth_map = {u: _auth_info(u, AuthMethod.UNAUTHENTICATED) for u in (
        "https://svc.example.com/z-api",
        "https://svc.example.com/a-api",
        "https://svc.example.com:8443/admin",
    )}
    unresolved = [{"host": "dead.example.com", "error": "NXDOMAIN"}]
    ip_map = {"svc.example.com": ["10.0.0.5"]}

    report = build_report(sources, auth_map, unresolved, ip_map)

    services = report.service_map
    # Sorted, deduped across sources, and the templated URL is quarantined out.
    assert [u.url for u in services["https://svc.example.com"].urls] == [
        "https://svc.example.com/a-api",
        "https://svc.example.com/z-api",
    ]
    # Each entry carries that URL's own evidence, not just its name.
    assert services["https://svc.example.com"].url_map[
        "https://svc.example.com/a-api"] == UrlEvidence(
            url="https://svc.example.com/a-api", http_method=HttpMethod.HEAD,
            status_code=200,
            detected_method=AuthMethod.UNAUTHENTICATED,
            sources=["network: https://svc.example.com/config.json"])
    # The other port's URL didn't leak into the first service's list.
    assert [u.url for u in services["https://svc.example.com:8443"].urls] == [
        "https://svc.example.com:8443/admin",
    ]
    assert [u.url for u in services["https://dead.example.com"].urls] == [
        "https://dead.example.com/gone",
    ]


def test_report_lists_synthesized_roots_with_their_trigger():
    """A host root probed on our own initiative is listed among the service's
    URLs — it is the evidence behind the verdict — with the path that set it
    off as its only source, so the report never implies the config referenced
    `/`."""
    sources = [
        ConfigSource(origin="js: https://app/bundle.js",
                     urls_found=["https://svc.example.com/api"]),
        ConfigSource(origin="synthesized: https://svc.example.com/api",
                     urls_found=["https://svc.example.com/"]),
    ]
    auth_map = {
        "https://svc.example.com/api": _auth_info(
            "https://svc.example.com/api", AuthMethod.UNKNOWN, status=401),
        "https://svc.example.com/": AuthInfo(
            url="https://svc.example.com/",
            probe_result=ProbeResult(
                url="https://svc.example.com/", http_method=HttpMethod.HEAD, status_code=401,
                www_authenticate="NTLM", detected_method=AuthMethod.NTLM),
        ),
    }
    report = build_report(sources, auth_map, [], {"svc.example.com": ["10.0.0.5"]})

    svc = report.service_map["https://svc.example.com"]
    assert svc.auth_verdict is AuthMethod.NTLM   # the root's disclosure won
    assert svc.verdict_url == "https://svc.example.com/"
    assert svc.urls_probed == 2
    assert len(svc.urls) == 2                    # and the counts reconcile
    # The root is present with the raw challenge that produced the verdict,
    # and names the path it was probed for rather than any config.
    assert svc.url_map["https://svc.example.com/"] == UrlEvidence(
        url="https://svc.example.com/", http_method=HttpMethod.HEAD, status_code=401,
        www_authenticate="NTLM", detected_method=AuthMethod.NTLM,
        sources=["synthesized: https://svc.example.com/api"],
    )
    # The referenced path keeps its own weaker verdict and its config source.
    # Nothing is read back onto it from the root.
    api = svc.url_map["https://svc.example.com/api"]
    assert api == UrlEvidence(
        url="https://svc.example.com/api", http_method=HttpMethod.HEAD, status_code=401,
        detected_method=AuthMethod.UNKNOWN,
        sources=["js: https://app/bundle.js"],
    )


def test_report_urls_carry_their_sources():
    """Each service URL carries `sources`: the config origins that referenced
    it. Plural and in discovery order, since one URL is routinely compiled into
    several bundles."""
    sources = [
        ConfigSource(
            origin="js: https://app/vendor.js",
            urls_found=[
                "https://svc.example.com/shared",
                "https://svc.example.com/vendor-only",  # discovered, unprobed
            ],
        ),
        ConfigSource(  # a second origin referencing one of the same URLs
            origin="network: https://app/config.json",
            urls_found=["https://svc.example.com/shared"],
        ),
    ]
    auth_map = {
        "https://svc.example.com/shared": _auth_info(
            "https://svc.example.com/shared", AuthMethod.UNAUTHENTICATED),
    }
    report = build_report(sources, auth_map, [], {"svc.example.com": ["10.0.0.5"]})

    urls = report.service_map["https://svc.example.com"].url_map
    # Every origin that referenced it, deduped, in the order the sources were
    # collected: the fan-out is itself signal that this is real app config and
    # not one vendor bundle's string noise.
    assert urls["https://svc.example.com/shared"].sources == [
        "js: https://app/vendor.js",
        "network: https://app/config.json",
    ]
    # Discovered but never probed: the provenance is then the whole entry.
    assert urls["https://svc.example.com/vendor-only"] == UrlEvidence(
        url="https://svc.example.com/vendor-only",
        sources=["js: https://app/vendor.js"])


def test_report_hosts_that_failed_dns_are_services():
    """A host DNS could not answer for is reported as services like any other,
    one per origin its URLs name: DNS has no notion of port, but a VIP does, so
    one bad name takes down every scheme and port that is its own service.

    Nothing was probed, so each has no ips and no probes, and it and each of its
    URLs carry DNS_FAILED, the URL with the lookup's error and its provenance. A
    name that doesn't resolve from the scanner's vantage point is a finding on
    an internal estate, and the path is what makes it one."""
    sources = [
        ConfigSource(
            origin="network: https://app/config.json",
            urls_found=[
                "https://internal-only.corp/api/v1",
                "https://internal-only.corp:8443/admin",  # same name, own service
                "https://ok.example.com/x",
            ],
        ),
        ConfigSource(  # a second origin, so the provenance survives plural
            origin="js: https://app/main.js",
            urls_found=["https://internal-only.corp/api/v1"],
        ),
    ]
    report = build_report(
        sources,
        {"https://ok.example.com/x": _auth_info(
            "https://ok.example.com/x", AuthMethod.UNAUTHENTICATED)},
        [{"host": "internal-only.corp", "error": "NXDOMAIN"},
         {"host": "never-referenced.corp", "error": "timeout"}],
        {"ok.example.com": ["1.2.3.4"]},
    )

    services = report.service_map
    assert set(services) == {
        "https://internal-only.corp",
        "https://internal-only.corp:8443",
        "https://ok.example.com",
    }
    for key in ("https://internal-only.corp", "https://internal-only.corp:8443"):
        failed = services[key]
        assert failed.ips == []
        assert failed.auth_verdict is AuthMethod.DNS_FAILED
        assert failed.urls_probed == 0
    # Every origin that referenced the URL survives, in discovery order.
    assert services["https://internal-only.corp"].url_map == {
        "https://internal-only.corp/api/v1": UrlEvidence(
            url="https://internal-only.corp/api/v1",
            detected_method=AuthMethod.DNS_FAILED, error="NXDOMAIN",
            sources=["network: https://app/config.json", "js: https://app/main.js"]),
    }
    assert services["https://internal-only.corp:8443"].url_map == {
        "https://internal-only.corp:8443/admin": UrlEvidence(
            url="https://internal-only.corp:8443/admin",
            detected_method=AuthMethod.DNS_FAILED, error="NXDOMAIN",
            sources=["network: https://app/config.json"]),
    }
    # The resolved host beside them is untouched.
    assert services["https://ok.example.com"].auth_verdict is AuthMethod.UNAUTHENTICATED
    # A failed host no clean URL named has no origin to be listed under.
    assert "never-referenced.corp" not in {s.origin.host for s in report.services}

    # The services account for every clean URL the configs referenced.
    placed = {u.url for svc in report.services for u in svc.urls}
    extracted = {u for src in sources for u in src.urls_found
                 if _classify_url(u) is None}
    assert placed == extracted


def test_report_urls_carry_redirect_location():
    """A redirect's Location is kept as the evidence behind the verdict:
    `oauth` says a service federates, the header says to whom."""
    sources = [ConfigSource(
        origin="js: https://app/bundle.js",
        urls_found=["https://svc.example.com/api"],
    )]
    auth_map = {
        "https://svc.example.com/api": AuthInfo(
            url="https://svc.example.com/api",
            probe_result=ProbeResult(
                url="https://svc.example.com/api", http_method=HttpMethod.HEAD,
                status_code=302, www_authenticate=None, detected_method=AuthMethod.OAUTH,
                location="https://sso.corp.local/oauth2/authorize?client_id=x"),
        ),
    }
    report = build_report(sources, auth_map, [], {"svc.example.com": ["10.0.0.5"]})

    assert report.service_map["https://svc.example.com"].url_map[
        "https://svc.example.com/api"] == UrlEvidence(
        url="https://svc.example.com/api", http_method=HttpMethod.HEAD, status_code=302,
        detected_method=AuthMethod.OAUTH,
        location="https://sso.corp.local/oauth2/authorize?client_id=x",
        sources=["js: https://app/bundle.js"],
    )


def test_report_merges_config_and_redirect_sources():
    """A URL the config named that a redirect also points at lists both origins,
    in discovery order: the `redirect:` provenance composes with the rest."""
    sources = [
        ConfigSource(origin="network: https://app/config.json",
                     urls_found=["https://sso.corp.local/login"]),
        ConfigSource(origin="redirect: https://svc.example.com/api",
                     urls_found=["https://sso.corp.local/login"]),
    ]
    report = build_report(sources, {}, [], {"sso.corp.local": ["10.0.0.9"]})

    urls = report.service_map["https://sso.corp.local"].url_map
    assert urls["https://sso.corp.local/login"].sources == [
        "network: https://app/config.json",
        "redirect: https://svc.example.com/api",
    ]


def test_report_quarantines_malformed_redirect_target():
    """A redirect target _classify_url rejects (an IPv6 literal is `bad_host`)
    lands in suspect_urls with its redirect provenance rather than vanishing."""
    sources = [ConfigSource(origin="redirect: https://svc.example.com/api",
                            urls_found=["http://[::1]:8080/x"])]
    report = build_report(sources, {}, [], {})

    assert report.services == []
    assert [(s.url, s.reason, s.sources) for s in report.suspect_urls] == [
        ("http://[::1]:8080/x", "bad_host", ["redirect: https://svc.example.com/api"]),
    ]


def test_report_unreferenced_failed_host_adds_no_service():
    sources = [ConfigSource(
        origin="js: https://test/bundle.js",
        urls_found=["https://real.example.com/api"],
    )]
    unresolved = [{"host": "x.invalid", "error": "NXDOMAIN"}]
    report = build_report(sources, unresolved=unresolved)
    # The referenced host is not in `unresolved`, so it is an ordinary service,
    # and the failed host no URL named has no origin to report.
    assert list(report.service_map) == ["https://real.example.com"]
    assert report.services[0].auth_verdict is None


def test_report_resolved_host_carries_its_ips():
    sources = [ConfigSource(
        origin="js: https://test/bundle.js",
        urls_found=["https://real.example.com/api"],
    )]
    report = build_report(sources, {}, [], {"real.example.com": ["10.0.0.9"]})
    assert isinstance(report, ScanReport)
    svc = report.service_map["https://real.example.com"]
    assert svc.ips == ["10.0.0.9"]
    assert svc.auth_verdict is None  # resolved, just not probed
