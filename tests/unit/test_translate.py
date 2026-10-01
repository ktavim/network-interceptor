"""Tests for core.translate."""
import pytest

from core.db import ServiceRow, UrlRow
from core.enums import AuthMethod, Severity
from core.translate import (
    service_to_row,
    services_to_rows,
    severity_for,
    tag_to_auth_method,
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
        # severity_for clears whatever it does not name, so a new AuthMethod
        # has to be placed in a tier here before it can slip through as cleared.
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
