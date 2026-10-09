"""Tests for core.translate."""
import pytest

from config_tracer.models import AuthMethod as TracerAuthMethod
from config_tracer.models import HttpMethod, Origin
from config_tracer.report import ScanReport, ServiceReport, UrlEvidence
from core.db import ServiceRow, UrlRow
from core.enums import AuthMethod, Severity, SourceKind
from core.translate import (
    parse_source,
    service_to_row,
    services_to_rows,
    severity_for,
    tag_to_auth_method,
    tracer_report_to_rows,
    tracer_url_to_row,
    url_to_row,
)


class TestSeverityFor:
    BLOCKERS = [AuthMethod.ntlm, AuthMethod.basic, AuthMethod.other]
    REVIEW = [
        AuthMethod.negotiate,
        AuthMethod.no_response,
        AuthMethod.dns_failed,
        AuthMethod.unknown,
    ]
    CLEARED = [
        AuthMethod.kerberos,
        AuthMethod.oauth,
        AuthMethod.login_redirect,
        AuthMethod.bearer,
        AuthMethod.api_key,
        AuthMethod.unauthenticated,
    ]

    @pytest.mark.parametrize("auth_method", BLOCKERS)
    def test_blockers(self, auth_method):
        # The known-unsupported schemes and, since only named schemes are
        # supported for the publish, any real scheme the crawler could not name.
        assert severity_for(auth_method) == Severity.blocker

    @pytest.mark.parametrize("auth_method", REVIEW)
    def test_review(self, auth_method):
        # What cannot be told yet: SPNEGO with its mechanism unresolved, an
        # origin nothing on which answered, a host that did not resolve, or
        # an answer that names no scheme.
        assert severity_for(auth_method) == Severity.review

    @pytest.mark.parametrize("auth_method", CLEARED)
    def test_cleared(self, auth_method):
        assert severity_for(auth_method) == Severity.cleared

    def test_every_auth_method_is_pinned(self):
        # severity_for sends whatever it does not name to review, so a new
        # AuthMethod has to be given a deliberate tier here rather than
        # defaulting there.
        assert set(self.BLOCKERS + self.REVIEW + self.CLEARED) == set(AuthMethod)


class TestTagToAuthMethod:
    def test_other_marker_maps_to_other(self):
        # The interceptor's else-branch 401 challenge -> AuthMethod.other.
        assert tag_to_auth_method("other") == AuthMethod.other

    def test_unclassified_stays_unknown(self):
        assert tag_to_auth_method("something weird") == AuthMethod.unknown


class TestServiceToRow:
    def test_carries_the_origin_triple(self):
        row = service_to_row("scan-1", {
            "scheme": "https",
            "host": "api.example.com",
            "port": 8443,
            "authentication": "basic",
        })
        assert row["scan_id"] == "scan-1"
        assert (row["scheme"], row["host"], row["port"]) == ("https", "api.example.com", 8443)
        assert row["auth_method"] == AuthMethod.basic.value
        assert row["severity"] == Severity.blocker.value
        assert row["ips"] is None

    def test_request_count_counts_the_urls(self):
        urls = [{"url": f"https://a.com/{i}"} for i in range(3)]
        row = service_to_row("scan-1", {
            "scheme": "https", "host": "a.com", "port": 443, "urls": urls,
        })
        assert row["request_count"] == 3

    def test_ips_pass_through(self):
        row = service_to_row("scan-1", {
            "scheme": "https", "host": "a.com", "port": 443, "ips": ["10.0.0.1", "10.0.0.2"],
        })
        assert row["ips"] == ["10.0.0.1", "10.0.0.2"]

    def test_missing_origin_field_is_a_producer_bug(self):
        # scheme/host/port are NOT NULL identity columns: an entry without them
        # must fail loudly here rather than persist a blank origin.
        with pytest.raises(KeyError):
            service_to_row("scan-1", {"host": "api.example.com", "authentication": "basic"})


# One aggregate_by_origin per-request entry: the interceptor's record as captured.
_URL_ITEM = {
    "method": "GET",
    "url": "https://api.example.com/v1/items",
    "resource_type": "xhr",
    "status": 401,
    "authentication": "basic",
    "sent_auth_scheme": "Basic",
    "auth_challenge": 'Basic realm="x"',
    "redirect_url": None,
    "page_url": "https://app.example.com/page",
}


class TestUrlToRow:
    def test_links_service(self):
        row = url_to_row("service-1", _URL_ITEM)
        assert row["service_id"] == "service-1"
        assert row["method"] == "GET"
        assert row["url"] == "https://api.example.com/v1/items"
        assert row["resource_type"] == "xhr"
        assert row["status_code"] == 401
        assert row["failure_reason"] is None
        assert row["auth_method"] == AuthMethod.basic.value
        assert row["sent_auth_scheme"] == "Basic"
        assert row["auth_challenge"] == 'Basic realm="x"'
        assert row["redirect_url"] is None
        assert row["page_url"] == "https://app.example.com/page"
        assert row["id"]

    def test_marks_the_row_as_the_interceptors(self):
        row = url_to_row("service-1", _URL_ITEM)
        assert row["scanner"] == "interceptor"
        # Provenance strings are the tracer's; a captured request has page_url.
        assert row["sources"] == []

    @pytest.mark.parametrize("tag, expected", [
        ("", AuthMethod.unknown),
        ("basic", AuthMethod.basic),
        (" BEARER ", AuthMethod.bearer),
        ("something weird", AuthMethod.unknown),
    ])
    def test_auth_method_normalized(self, tag, expected):
        row = url_to_row("service-1", {**_URL_ITEM, "authentication": tag})
        assert row["auth_method"] == expected.value

    def test_defaults(self):
        row = url_to_row("service-1", {"url": "https://a.com/x"})
        assert row["method"] == ""
        assert row["resource_type"] == ""
        assert row["status_code"] == 0
        assert row["auth_method"] == AuthMethod.unknown.value
        assert row["sent_auth_scheme"] is None
        assert row["auth_challenge"] is None
        assert row["redirect_url"] is None
        assert row["page_url"] == ""
        assert row["failure_reason"] is None

    def test_redirect_url_carried(self):
        row = url_to_row("service-1", {**_URL_ITEM, "status": 302, "redirect_url": "https://a.com/login"})
        assert row["redirect_url"] == "https://a.com/login"

    def test_failure_reason_carried(self):
        row = url_to_row("service-1", {**_URL_ITEM, "status": 0, "failure_reason": "net::ERR_ABORTED"})
        assert row["status_code"] == 0
        assert row["failure_reason"] == "net::ERR_ABORTED"

    def test_missing_url_is_a_producer_bug(self):
        with pytest.raises(KeyError):
            url_to_row("service-1", {"method": "GET"})

    def test_row_keys_match_the_table(self):
        # core.jobs does UrlRow(**row): an unknown key would TypeError, and a
        # missing one would silently fall back to the column default.
        row = url_to_row("service-1", _URL_ITEM)
        assert set(row) == set(UrlRow.__table__.columns.keys())


def _service(host: str, urls: list) -> dict:
    return {
        "scheme": "https",
        "host": host,
        "port": 443,
        "authentication": "bearer",
        "urls": urls,
    }


class TestServicesToRows:
    def test_returns_services_and_urls_linked_by_service_id(self):
        services = [
            _service("a.com", [
                {**_URL_ITEM, "url": "https://a.com/1"},
                {**_URL_ITEM, "url": "https://a.com/2"},
            ]),
            _service("b.com", [{**_URL_ITEM, "url": "https://b.com/1"}]),
        ]
        service_rows, url_rows = services_to_rows("scan-1", services)
        assert len(service_rows) == 2
        assert len(url_rows) == 3
        by_host = {s["host"]: s["id"] for s in service_rows}
        assert [(u["service_id"], u["url"]) for u in url_rows] == [
            (by_host["a.com"], "https://a.com/1"),
            (by_host["a.com"], "https://a.com/2"),
            (by_host["b.com"], "https://b.com/1"),
        ]

    def test_service_row_has_no_urls_key(self):
        # core.jobs does ServiceRow(**row); an extra key would raise TypeError.
        service_rows, _ = services_to_rows("scan-1", [_service("a.com", [_URL_ITEM])])
        assert "urls" not in service_rows[0]
        assert set(service_rows[0]) == set(ServiceRow.__table__.columns.keys())

    def test_service_without_urls_yields_no_url_rows(self):
        service = _service("a.com", [])
        del service["urls"]
        service_rows, url_rows = services_to_rows("scan-1", [service])
        assert len(service_rows) == 1
        assert url_rows == []

    def test_evidence_url_id_is_the_url_row_at_evidence_index(self):
        service = _service("a.com", [
            {**_URL_ITEM, "url": "https://a.com/1"},
            {**_URL_ITEM, "url": "https://a.com/2"},
        ])
        service["evidence_index"] = 1
        service_rows, url_rows = services_to_rows("scan-1", [service])
        assert service_rows[0]["evidence_url_id"] == url_rows[1]["id"]
        assert url_rows[1]["url"] == "https://a.com/2"

    def test_evidence_index_is_relative_to_each_service(self):
        services = [
            _service("a.com", [_URL_ITEM]),
            _service("b.com", [_URL_ITEM, _URL_ITEM]),
        ]
        services[0]["evidence_index"] = 0
        services[1]["evidence_index"] = 1
        service_rows, url_rows = services_to_rows("scan-1", services)
        assert service_rows[0]["evidence_url_id"] == url_rows[0]["id"]
        assert service_rows[1]["evidence_url_id"] == url_rows[2]["id"]

    def test_service_without_evidence_index_points_nowhere(self):
        service_rows, _ = services_to_rows("scan-1", [_service("a.com", [_URL_ITEM])])
        assert service_rows[0]["evidence_url_id"] is None

    def test_empty(self):
        assert services_to_rows("scan-1", []) == ([], [])


def _probed(url: str, method=TracerAuthMethod.UNAUTHENTICATED, status=200, **fields) -> UrlEvidence:
    """One URL of a tracer report, as a HEAD probe that got an answer."""
    fields.setdefault("sources", ["dom: inline script (window.__CONFIG__)"])
    return UrlEvidence(
        url=url, http_method=HttpMethod.HEAD, status_code=status, detected_method=method, **fields
    )


def _traced(urls, verdict, origin=Origin("https", "api.example.com", 443), ips=("10.0.0.1",)) -> ServiceReport:
    return ServiceReport(
        origin=origin, ips=list(ips), auth_verdict=verdict, urls_probed=len(urls), urls=list(urls),
    )


def _report(*services: ServiceReport) -> ScanReport:
    return ScanReport(services=list(services), suspect_urls=[])


class TestTracerUrlToRow:
    def test_probe_fills_the_columns_of_a_captured_request(self):
        row = tracer_url_to_row("service-1", _probed(
            "https://api.example.com/v1/items", TracerAuthMethod.BASIC, 401,
            www_authenticate='Basic realm="x"',
        ))
        assert row["id"]
        assert row["service_id"] == "service-1"
        assert row["scanner"] == "tracer"
        assert row["method"] == "HEAD"
        assert row["url"] == "https://api.example.com/v1/items"
        assert row["resource_type"] == "probe"
        assert row["status_code"] == 401
        assert row["failure_reason"] is None
        assert row["auth_method"] == AuthMethod.basic.value
        assert row["auth_challenge"] == 'Basic realm="x"'
        assert row["redirect_url"] is None
        # The probes are anonymous and sent from no page.
        assert row["sent_auth_scheme"] is None
        assert row["page_url"] == ""
        assert row["sources"] == ["dom: inline script (window.__CONFIG__)"]

    def test_row_keys_match_the_table(self):
        row = tracer_url_to_row("service-1", _probed("https://api.example.com/x"))
        assert set(row) == set(UrlRow.__table__.columns.keys())

    def test_url_is_stripped_like_a_captured_request(self):
        # The tracer keeps a config URL verbatim, key in the query string and all.
        row = tracer_url_to_row("service-1", _probed("https://user:pw@api.example.com/v1?key=sk-123#frag"))
        assert row["url"] == "https://api.example.com/v1"

    def test_get_fallback_is_the_method(self):
        evidence = _probed("https://api.example.com/x")
        evidence.http_method = HttpMethod.GET
        assert tracer_url_to_row("service-1", evidence)["method"] == "GET"

    @pytest.mark.parametrize("location, expected", [
        # Relative, as servers commonly send it.
        ("/login?next=%2Fdashboard", "https://api.example.com/login"),
        ("signin", "https://api.example.com/app/signin"),
        ("https://login.example.org/authorize?client_id=abc&state=xyz#frag", "https://login.example.org/authorize"),
    ])
    def test_location_is_resolved_against_the_url_then_stripped(self, location, expected):
        row = tracer_url_to_row("service-1", _probed(
            "https://api.example.com/app/home?tab=1", TracerAuthMethod.LOGIN_REDIRECT, 302, location=location,
        ))
        assert row["redirect_url"] == expected

    def test_location_of_a_response_that_is_not_a_redirect_is_dropped(self):
        # redirect_url is a 3xx's target; a 201's Location names what was created.
        row = tracer_url_to_row("service-1", _probed("https://api.example.com/x", status=201, location="/x/1"))
        assert row["redirect_url"] is None

    def test_no_response_is_status_0_with_the_error(self):
        row = tracer_url_to_row("service-1", UrlEvidence(
            url="https://api.example.com/x", http_method=HttpMethod.HEAD, status_code=None,
            detected_method=TracerAuthMethod.NO_RESPONSE, error="timeout", sources=["js: https://app/a.js"],
        ))
        assert (row["method"], row["status_code"], row["failure_reason"]) == ("HEAD", 0, "timeout")
        assert row["auth_method"] == AuthMethod.no_response.value

    def test_dns_failed_url_names_no_request(self):
        row = tracer_url_to_row("service-1", UrlEvidence(
            url="https://internal-only.corp/api", detected_method=TracerAuthMethod.DNS_FAILED,
            error="NXDOMAIN", sources=["js: https://app/a.js"],
        ))
        assert (row["method"], row["status_code"], row["failure_reason"]) == ("", 0, "NXDOMAIN")
        assert row["auth_method"] == AuthMethod.dns_failed.value

    @pytest.mark.parametrize("verdict", list(TracerAuthMethod))
    def test_every_tracer_verdict_is_in_the_combined_vocabulary(self, verdict):
        row = tracer_url_to_row("service-1", _probed("https://api.example.com/x", verdict))
        assert row["auth_method"] == verdict.value

    @pytest.mark.parametrize("verdict", ["digest", "", None])
    def test_verdict_outside_the_vocabulary_raises(self, verdict):
        # Not stored as unknown, as tag_to_auth_method would: a new tracer value
        # has to be added to AuthMethod, and None is a URL the tracer never probed.
        with pytest.raises(ValueError):
            tracer_url_to_row("service-1", _probed("https://api.example.com/x", verdict))

    def test_urls_named_in_sources_are_stripped_too(self):
        row = tracer_url_to_row("service-1", _probed("https://api.example.com/x", sources=[
            "network: https://app.example.com/config.json?v=3",
            "js: https://app.example.com/main.js?token=abc",
            "redirect: https://sso.example.com/start?state=1",
            # The same redirecting URL once stripped.
            "redirect: https://sso.example.com/start?state=2",
            "synthesized: https://api.example.com/v1/data?key=sk-123",
            'dom: <script type="application/json">',
            "dom: referenced file /settings.json",
        ]))
        assert row["sources"] == [
            "network: https://app.example.com/config.json",
            "js: https://app.example.com/main.js",
            "redirect: https://sso.example.com/start",
            "synthesized: https://api.example.com/v1/data",
            'dom: <script type="application/json">',
            "dom: referenced file /settings.json",
        ]

    @pytest.mark.parametrize("source", ["dom", "config: /x", "page: https://app/", "network:", ""])
    def test_source_outside_the_provenance_vocabulary_raises(self, source):
        # Like a verdict outside AuthMethod: a string the API could give no kind
        # (Service.sources) is a producer that drifted, and is refused here
        # rather than failing every read of the service.
        with pytest.raises(ValueError):
            tracer_url_to_row("service-1", _probed("https://api.example.com/x", sources=[source]))


class TestParseSource:
    @pytest.mark.parametrize("source, expected", [
        ("network: https://app/config.json", (SourceKind.network, "https://app/config.json")),
        ("js: https://app/main.js", (SourceKind.js, "https://app/main.js")),
        ('dom: <script type="application/json">', (SourceKind.dom, '<script type="application/json">')),
        ("dom: inline script (window.__CONFIG__)", (SourceKind.dom, "inline script (window.__CONFIG__)")),
        ("redirect: https://sso/start", (SourceKind.redirect, "https://sso/start")),
        ("synthesized: https://api/v1/data", (SourceKind.synthesized, "https://api/v1/data")),
    ])
    def test_splits_the_kind_from_what_it_names(self, source, expected):
        assert parse_source(source) == expected

    def test_splits_at_the_first_separator(self):
        # What a dom source names is prose, and may carry the separator itself.
        assert parse_source("dom: referenced file /a: b.js") == (SourceKind.dom, "referenced file /a: b.js")

    @pytest.mark.parametrize("source", ["dom", "config: /x", "page: https://app/", "network:", ""])
    def test_outside_the_tracers_vocabulary_raises(self, source):
        # page is the interceptor's kind, never a stored string; the rest name no kind.
        with pytest.raises(ValueError):
            parse_source(source)


class TestTracerReportToRows:
    def test_service_row_is_the_origin_with_the_tracers_verdict(self):
        report = _report(_traced(
            [_probed("https://api.example.com:8443/a"), _probed("https://api.example.com:8443/b")],
            TracerAuthMethod.UNAUTHENTICATED,
            origin=Origin("https", "api.example.com", 8443),
            ips=["10.0.0.1", "10.0.0.2"],
        ))
        [row], url_rows = tracer_report_to_rows("scan-1", report)
        assert row["scan_id"] == "scan-1"
        assert (row["scheme"], row["host"], row["port"]) == ("https", "api.example.com", 8443)
        assert (row["auth_method"], row["severity"]) == ("unauthenticated", "cleared")
        assert row["request_count"] == 2
        assert row["ips"] == ["10.0.0.1", "10.0.0.2"]
        assert row["excluded"] is False
        assert [u["service_id"] for u in url_rows] == [row["id"], row["id"]]

    def test_service_row_keys_match_the_table(self):
        # core.jobs does ServiceRow(**row), as for the interceptor's rows.
        [row], _ = tracer_report_to_rows("scan-1", _report(
            _traced([_probed("https://api.example.com/a")], TracerAuthMethod.UNAUTHENTICATED)
        ))
        assert set(row) == set(ServiceRow.__table__.columns.keys())

    def test_dns_failed_service_has_no_addresses(self):
        failed = UrlEvidence(
            url="https://internal-only.corp/api", detected_method=TracerAuthMethod.DNS_FAILED,
            error="NXDOMAIN", sources=["js: https://app/a.js"],
        )
        [row], _ = tracer_report_to_rows("scan-1", _report(_traced(
            [failed], TracerAuthMethod.DNS_FAILED, origin=Origin("https", "internal-only.corp", 443), ips=[],
        )))
        assert (row["auth_method"], row["severity"]) == ("dns_failed", "review")
        # NULL, as for an interceptor service whose host did not resolve.
        assert row["ips"] is None

    def test_evidence_is_the_row_of_the_verdict_url(self):
        report = _report(_traced([
            _probed("https://api.example.com/a"),
            _probed("https://api.example.com/b", TracerAuthMethod.BASIC, 401),
            _probed("https://api.example.com/c", TracerAuthMethod.BASIC, 401),
        ], TracerAuthMethod.BASIC))
        [row], url_rows = tracer_report_to_rows("scan-1", report)
        # The first URL in code-point order that carries the verdict.
        assert row["evidence_url_id"] == url_rows[1]["id"]
        assert url_rows[1]["url"] == "https://api.example.com/b"

    def test_evidence_is_found_among_urls_that_strip_to_the_same_one(self):
        report = _report(_traced([
            _probed("https://api.example.com/x?open=1"),
            _probed("https://api.example.com/x?secure=1", TracerAuthMethod.NTLM, 401),
        ], TracerAuthMethod.NTLM))
        [row], url_rows = tracer_report_to_rows("scan-1", report)
        assert [u["url"] for u in url_rows] == ["https://api.example.com/x"] * 2
        assert row["evidence_url_id"] == url_rows[1]["id"]
        assert url_rows[1]["auth_method"] == "ntlm"

    def test_evidence_is_each_services_own(self):
        report = _report(
            _traced([_probed("https://a.example.com/1")], TracerAuthMethod.UNAUTHENTICATED,
                    origin=Origin("https", "a.example.com", 443)),
            _traced([
                _probed("https://b.example.com/1"),
                _probed("https://b.example.com/2", TracerAuthMethod.BEARER, 401),
            ], TracerAuthMethod.BEARER, origin=Origin("https", "b.example.com", 443)),
        )
        service_rows, url_rows = tracer_report_to_rows("scan-1", report)
        assert [s["evidence_url_id"] for s in service_rows] == [url_rows[0]["id"], url_rows[2]["id"]]
        assert [u["service_id"] for u in url_rows] == [
            service_rows[0]["id"], service_rows[1]["id"], service_rows[1]["id"],
        ]

    def test_service_nothing_was_probed_on_raises(self):
        # A scan never produces one; the report is refused, not stored with a gap.
        unprobed = _traced([UrlEvidence(url="https://api.example.com/a", sources=["js: https://app/a.js"])], None)
        with pytest.raises(ValueError):
            tracer_report_to_rows("scan-1", _report(unprobed))

    def test_empty(self):
        assert tracer_report_to_rows("scan-1", _report()) == ([], [])
