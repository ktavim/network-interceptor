"""Tests for api.serialize."""
from datetime import datetime, timezone

from api.serialize import published_origin_to_schema, service_to_schema, sources_to_schema
from core.db import PublishedOriginRow, ServiceRow, UrlRow
from core.enums import AuthMethod, Scanner, Severity


def _url(scanner: Scanner, **fields) -> UrlRow:
    """A url row with only what sources_to_schema reads: a tracer row's sources,
    or an interceptor row's page_url."""
    fields.setdefault("sources", [])
    fields.setdefault("page_url", "")
    return UrlRow(scanner=scanner.value, **fields)


def _listed(sources) -> list[tuple[str, str]]:
    return [(source.kind, source.value) for source in sources]


def _service(severity: Severity, **fields) -> ServiceRow:
    """A service row with what service_to_schema reads. No session, so the
    column defaults are given here."""
    return ServiceRow(
        id="svc", scheme="https", host="a.example", port=443,
        auth_method=AuthMethod.ntlm.value, severity=severity.value,
        request_count=1, ips=None, excluded=False, **fields,
    )


_ADDED = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)


def _entry(**fields) -> PublishedOriginRow:
    return PublishedOriginRow(
        id="pub_1", scheme="https", host="a.example", port=443, note="vs_legacy",
        added_by="jchen", added_at=_ADDED, **fields,
    )


class TestServiceToSchema:
    def test_without_a_registry_entry(self):
        service = service_to_schema(_service(Severity.blocker), None, [], [])
        assert (service.severity, service.published_origin) == ("blocker", None)

    def test_a_published_service_carries_its_entry(self):
        service = service_to_schema(
            _service(Severity.published, published_origin_id="pub_1"), None, [], [], _entry()
        )
        # The label is the scanners'; the severity is the registry's.
        assert (service.auth_method, service.severity) == ("ntlm", "published")
        entry = service.published_origin
        assert (entry.id, entry.note, entry.added_by, entry.added_at, entry.removed_at, entry.removed_by) == (
            "pub_1", "vs_legacy", "jchen", "2026-10-09T12:00:00+00:00", None, None,
        )

    def test_a_removed_entry_says_so(self):
        removed = datetime(2026, 10, 10, tzinfo=timezone.utc)
        entry = published_origin_to_schema(_entry(removed_at=removed, removed_by="jchen"))
        assert (entry.removed_at, entry.removed_by) == ("2026-10-10T00:00:00+00:00", "jchen")


class TestSourcesToSchema:
    def test_each_tracer_source_is_its_kind_and_what_it_names(self):
        sources = sources_to_schema([_url(Scanner.tracer, sources=[
            "js: https://app/main.js", 'dom: <script type="application/json">',
        ])])
        assert _listed(sources) == [
            ("dom", '<script type="application/json">'), ("js", "https://app/main.js"),
        ]

    def test_an_interceptor_rows_page_is_a_source_of_kind_page(self):
        sources = sources_to_schema([_url(Scanner.interceptor, page_url="https://app/login")])
        assert _listed(sources) == [("page", "https://app/login")]

    def test_a_source_two_rows_share_is_listed_once(self):
        rows = [
            _url(Scanner.tracer, sources=["network: https://app/config.json", "js: https://app/a.js"]),
            _url(Scanner.tracer, sources=["network: https://app/config.json"]),
            _url(Scanner.interceptor, page_url="https://app/"),
            _url(Scanner.interceptor, page_url="https://app/"),
        ]
        assert _listed(sources_to_schema(rows)) == [
            ("js", "https://app/a.js"), ("network", "https://app/config.json"), ("page", "https://app/"),
        ]

    def test_sorted_by_kind_then_value_whatever_the_row_order(self):
        rows = [
            _url(Scanner.interceptor, page_url="https://app/b"),
            _url(Scanner.tracer, sources=["synthesized: https://api/x", "redirect: https://sso/start"]),
            _url(Scanner.interceptor, page_url="https://app/a"),
            _url(Scanner.tracer, sources=["dom: inline script (window.__CONFIG__)", "network: https://app/c.json"]),
        ]
        listed = _listed(sources_to_schema(rows))
        assert listed == _listed(sources_to_schema(rows[::-1]))
        assert listed == [
            ("dom", "inline script (window.__CONFIG__)"),
            ("network", "https://app/c.json"),
            ("page", "https://app/a"),
            ("page", "https://app/b"),
            ("redirect", "https://sso/start"),
            ("synthesized", "https://api/x"),
        ]

    def test_rows_with_neither_sources_nor_a_page_add_nothing(self):
        # A tracer row's page_url is "" and an interceptor row's sources are [].
        assert sources_to_schema([_url(Scanner.tracer), _url(Scanner.interceptor)]) == []

    def test_empty(self):
        assert sources_to_schema([]) == []
