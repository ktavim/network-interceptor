"""Tests for api.serialize."""
from api.serialize import sources_to_schema
from core.db import UrlRow
from core.enums import Scanner


def _url(scanner: Scanner, **fields) -> UrlRow:
    """A url row with only what sources_to_schema reads: a tracer row's sources,
    or an interceptor row's page_url."""
    fields.setdefault("sources", [])
    fields.setdefault("page_url", "")
    return UrlRow(scanner=scanner.value, **fields)


def _listed(sources) -> list[tuple[str, str]]:
    return [(source.kind, source.value) for source in sources]


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
