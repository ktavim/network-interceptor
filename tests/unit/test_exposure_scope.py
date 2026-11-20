"""core.exposures' pure parts: what an exposure does with each service, what
blocks planning, and the default grouping."""
import pytest

from core.db import PublishedOriginRow, ServiceRow
from core.enums import ExposureScope
from core.exposures import assess, format_origin, propose_grouping, scope_of

BOTH = ["interceptor", "tracer"]


def _service(host, *, id=None, scheme="https", port=443, auth="bearer", severity="cleared",
             excluded=False, published_origin_id=None) -> ServiceRow:
    return ServiceRow(
        id=id or f"svc_{host}_{port}", scan_id="scan", scheme=scheme, host=host, port=port,
        auth_method=auth, severity=severity, excluded=excluded,
        published_origin_id=published_origin_id,
    )


def _entry(host, *, scheme="https", port=443, url=None, id=None) -> PublishedOriginRow:
    return PublishedOriginRow(id=id or f"pub_{host}", scheme=scheme, host=host, port=port, url=url)


def _registry(*entries):
    return {(e.scheme, e.host, e.port): e for e in entries}


def _assess(services, *, found_by=None, group_of=None, registry=(), scan_entries=None):
    return assess(
        services=services,
        found_by=found_by if found_by is not None else {s.id: BOTH for s in services},
        group_of=group_of if group_of is not None else {s.id: "grp" for s in services},
        registry=_registry(*registry),
        scan_entries=scan_entries or {},
    )


def _codes(assessment):
    return [(n.code, n.service_id) for n in assessment.blocked_by]


class TestScopeOf:
    def test_cleared_needs_a_vip(self):
        assert scope_of(_service("a"), {}).scope is ExposureScope.needs_vip

    def test_excluded_wins_over_everything(self):
        service = _service("a", severity="blocker", auth="ntlm", excluded=True)
        assert scope_of(service, _registry(_entry("a"))).scope is ExposureScope.excluded

    def test_published_on_the_scan_and_still_registered(self):
        entry = _entry("a")
        scope = scope_of(_service("a", severity="published", auth="ntlm"), _registry(entry))
        assert (scope.scope, scope.registry_entry) == (ExposureScope.published, entry)

    def test_registered_since_the_scan_is_published(self):
        entry = _entry("a")
        scope = scope_of(_service("a"), _registry(entry))
        assert (scope.scope, scope.registry_entry) == (ExposureScope.published, entry)

    def test_the_registry_matches_the_whole_origin(self):
        registry = _registry(_entry("a", port=8443), _entry("a", scheme="http", port=443))
        assert scope_of(_service("a"), registry).scope is ExposureScope.needs_vip

    def test_removed_since_the_scan_falls_back_on_a_method_that_clears(self):
        assert scope_of(_service("a", severity="published", auth="oauth"), {}).scope is ExposureScope.needs_vip

    def test_removed_since_the_scan_with_a_method_that_does_not_clear_is_unresolved(self):
        removed = _entry("a")
        scope = scope_of(_service("a", severity="published", auth="ntlm"), {}, removed)
        assert (scope.scope, scope.registry_entry) == (ExposureScope.unresolved, removed)


class TestAssess:
    def test_a_grouped_cleared_service_blocks_nothing(self):
        a = _service("a")
        result = _assess([a])
        assert (result.blocked_by, result.needs_vip_count) == ([], 1)
        assert result.services[a.id].warnings == ()

    def test_an_ungrouped_service(self):
        a, b = _service("a"), _service("b")
        assert _codes(_assess([a, b], group_of={a.id: "grp"})) == [("service_ungrouped", b.id)]

    def test_kerberos_is_flagged_but_counted(self):
        k = _service("k", auth="kerberos")
        result = _assess([k])
        assert _codes(result) == [("kerberos_unsupported", k.id)]
        assert result.needs_vip_count == 1

    def test_a_published_service_needs_its_entry_url_and_no_group(self):
        p = _service("p", severity="published", auth="ntlm")
        result = _assess([p], group_of={}, registry=[_entry("p")])
        assert _codes(result) == [("published_url_missing", p.id)]
        assert result.needs_vip_count == 0
        assert _assess([p], group_of={}, registry=[_entry("p", url="https://p.example.com")]).blocked_by == []

    def test_an_unresolved_service(self):
        u = _service("u", severity="published", auth="basic")
        assert _codes(_assess([u], group_of={})) == [("published_origin_removed", u.id)]

    def test_an_excluded_service_is_ignored(self):
        x = _service("x", severity="blocker", auth="ntlm", excluded=True)
        assert _assess([x], group_of={}).blocked_by == []

    def test_warnings_on_the_services_the_rewrite_map_covers(self):
        a = _service("a", auth="login_redirect")
        p = _service("p", severity="published")
        x = _service("x", excluded=True)
        result = _assess(
            [a, p, x], found_by={a.id: ["interceptor"], p.id: ["interceptor"], x.id: ["interceptor"]},
            registry=[_entry("p", url="https://p.example.com")],
        )
        assert [w.code for w in result.services[a.id].warnings] == ["interceptor_only", "login_redirect"]
        assert [w.code for w in result.services[p.id].warnings] == ["interceptor_only"]
        assert result.services[x.id].warnings == ()


class TestProposeGrouping:
    def test_one_group_per_host(self):
        a443, a8443, b = _service("a"), _service("a", port=8443), _service("b")
        assert propose_grouping([a443, a8443, b]) == [[a443.id, a8443.id], [b.id]]

    def test_the_previous_grouping_is_kept_for_shared_origins(self):
        a, b, c, d = _service("a"), _service("b"), _service("c"), _service("c", port=8443)
        previous = [
            [("https", "gone", 443)],
            [("https", "b", 443), ("https", "a", 443)],
            [("https", "c", 443)],
        ]
        # a and b stay together, c keeps its group and its new port joins it.
        assert propose_grouping([a, b, c, d], previous) == [[b.id, a.id], [c.id, d.id]]

    def test_a_new_host_gets_a_group_after_the_carried_ones(self):
        a, n = _service("a"), _service("new")
        assert propose_grouping([a, n], [[("https", "a", 443)]]) == [[a.id], [n.id]]


@pytest.mark.parametrize("origin, text", [
    (("https", "a.example", 443), "https://a.example"),
    (("http", "a.example", 80), "http://a.example"),
    (("https", "a.example", 8443), "https://a.example:8443"),
    (("http", "a.example", 443), "http://a.example:443"),
    (("https", "::1", 443), "https://[::1]"),
])
def test_format_origin(origin, text):
    assert format_origin(origin) == text
