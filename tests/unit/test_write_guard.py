"""Tests for crawler.network.write_guard."""
import json

import pytest
from unittest.mock import AsyncMock, MagicMock, PropertyMock

from config_loader import LoginConfig
from crawler.network.write_guard import (
    BLOCKED_FAILURE_REASON,
    WriteGuard,
    is_read_only_graphql,
)


def _gql(query, **extra):
    return json.dumps({"query": query, **extra})


@pytest.fixture
def guard(make_config):
    return WriteGuard(make_config())


@pytest.fixture
def make_request(mock_request):
    def _make(method="POST", url="http://localhost:8080/api/items", post_data=None):
        return mock_request(method=method, url=url, post_data=post_data)
    return _make


class TestIsReadOnlyGraphql:
    @pytest.mark.parametrize("query", [
        "{ me { id } }",
        "query { me { id } }",
        "query Me($id: ID!) { user(id: $id) { name } }",
        "  # leading comment\n query Me { me { id } }",
        "fragment F on User { id } query Q { me { ...F } }",
    ])
    def test_queries_are_read_only(self, query):
        assert is_read_only_graphql(_gql(query)) is True

    @pytest.mark.parametrize("query", [
        "mutation { deleteUser(id: 1) }",
        "mutation AddItem { addItem(name: \"x\") { id } }",
        "subscription { onEvent { id } }",
        # A mutation hidden behind a query in the same document.
        "query Q { me { id } } mutation M { addItem { id } }",
    ])
    def test_writes_are_not_read_only(self, query):
        assert is_read_only_graphql(_gql(query)) is False

    def test_mutation_word_in_a_string_or_comment_is_ignored(self):
        query = 'query { search(text: "mutation") { id } } # no mutation here'
        assert is_read_only_graphql(_gql(query)) is True

    def test_field_named_subscription_is_blocked_conservatively(self):
        assert is_read_only_graphql(_gql("query { me { subscription { plan } } }")) is False

    def test_batch_of_queries_is_read_only(self):
        body = json.dumps([{"query": "{ a }"}, {"query": "query { b }"}])
        assert is_read_only_graphql(body) is True

    def test_batch_with_one_mutation_is_not(self):
        body = json.dumps([{"query": "{ a }"}, {"query": "mutation { b }"}])
        assert is_read_only_graphql(body) is False

    def test_empty_batch_is_not(self):
        assert is_read_only_graphql("[]") is False

    def test_persisted_query_without_document_is_not(self):
        body = json.dumps({"operationName": "Me", "extensions": {"persistedQuery": {"sha256Hash": "abc"}}})
        assert is_read_only_graphql(body) is False

    @pytest.mark.parametrize("body", [None, "", "query=x&delete=1", "not json", '"a string"', "42"])
    def test_non_graphql_bodies_are_not(self, body):
        assert is_read_only_graphql(body) is False


class TestIsAllowed:
    @pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "get"])
    def test_safe_methods_pass(self, guard, make_request, method):
        assert guard.is_allowed(make_request(method=method)) is True

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "PROPFIND"])
    def test_state_changing_methods_are_blocked(self, guard, make_request, method):
        assert guard.is_allowed(make_request(method=method)) is False

    def test_external_writes_are_blocked_too(self, guard, make_request):
        assert guard.is_allowed(make_request(url="https://api.example.com/v1/orders")) is False

    def test_anything_passes_while_writes_are_allowed(self, guard, make_request):
        req = make_request()
        with guard.allow_writes():
            assert guard.is_allowed(req) is True
        assert guard.is_allowed(req) is False

    def test_allow_writes_restores_on_error(self, guard, make_request):
        with pytest.raises(RuntimeError):
            with guard.allow_writes():
                raise RuntimeError("login failed")
        assert guard.is_allowed(make_request()) is False

    def test_nested_allow_writes_keeps_outer_window(self, guard, make_request):
        req = make_request()
        with guard.allow_writes():
            with guard.allow_writes():
                pass
            assert guard.is_allowed(req) is True

    def test_login_url_and_below_pass(self, make_config, make_request):
        cfg = make_config(login=LoginConfig(
            login_url="https://sso.example.com/realms/corp", username="u", password="p"))
        guard = WriteGuard(cfg)
        token = "https://sso.example.com/realms/corp/protocol/openid-connect/token"
        assert guard.is_allowed(make_request(url=token)) is True
        assert guard.is_allowed(make_request(url="https://sso.example.com/realms/corp")) is True

    def test_other_paths_on_the_login_origin_are_blocked(self, make_config, make_request):
        cfg = make_config(login=LoginConfig(
            login_url="https://sso.example.com/realms/corp", username="u", password="p"))
        guard = WriteGuard(cfg)
        assert guard.is_allowed(make_request(url="https://sso.example.com/realms/other/x")) is False

    def test_allow_write_patterns_match_case_insensitively(self, make_config, make_request):
        guard = WriteGuard(make_config(allow_write_patterns=["/API/Search"]))
        assert guard.is_allowed(make_request(url="http://localhost:8080/api/search?q=1")) is True
        assert guard.is_allowed(make_request(url="http://localhost:8080/api/items")) is False

    def test_graphql_query_passes(self, guard, make_request):
        req = make_request(url="http://localhost:8080/graphql", post_data=_gql("{ me { id } }"))
        assert guard.is_allowed(req) is True

    def test_graphql_mutation_is_blocked(self, guard, make_request):
        req = make_request(url="http://localhost:8080/graphql", post_data=_gql("mutation { addItem { id } }"))
        assert guard.is_allowed(req) is False

    def test_undecodable_body_is_blocked(self, guard, make_request):
        req = make_request()
        type(req).post_data = PropertyMock(side_effect=UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad"))
        assert guard.is_allowed(req) is False


class TestAttach:
    async def test_routes_every_request_when_blocking(self, guard):
        context = MagicMock()
        context.route = AsyncMock()
        await guard.attach(context)
        context.route.assert_awaited_once_with("**/*", guard._handle_route)

    async def test_does_not_route_when_allowing(self, make_config):
        guard = WriteGuard(make_config(write_policy="allow"))
        context = MagicMock()
        context.route = AsyncMock()
        await guard.attach(context)
        assert guard.enabled is False
        context.route.assert_not_called()


class TestHandleRoute:
    @staticmethod
    def _route(request):
        route = MagicMock()
        route.request = request
        route.fallback = AsyncMock()
        route.abort = AsyncMock()
        return route

    async def test_allowed_request_falls_through(self, guard, make_request):
        req = make_request(method="GET")
        route = self._route(req)
        await guard._handle_route(route)
        route.fallback.assert_awaited_once()
        route.abort.assert_not_called()
        assert guard.was_blocked(req) is False
        assert guard.blocked_count == 0

    async def test_write_is_aborted_and_remembered(self, guard, make_request):
        req = make_request()
        route = self._route(req)
        await guard._handle_route(route)
        route.abort.assert_awaited_once_with("blockedbyclient")
        route.fallback.assert_not_called()
        assert guard.was_blocked(req) is True
        assert guard.blocked_count == 1

    async def test_blocked_is_by_identity(self, guard, make_request):
        # Two requests to the same method and URL: only the aborted one is blocked.
        blocked = make_request()
        other = make_request()
        await guard._handle_route(self._route(blocked))
        assert guard.was_blocked(other) is False

    async def test_log_strips_the_query(self, guard, make_request, caplog):
        req = make_request(url="https://api.example.com/v1/orders?token=secret")
        with caplog.at_level("INFO", logger="crawler.network.write_guard"):
            await guard._handle_route(self._route(req))
        assert "Write guard blocked POST https://api.example.com/v1/orders" in caplog.text
        assert "secret" not in caplog.text


def test_failure_reason_is_distinct_from_browser_errors():
    assert not BLOCKED_FAILURE_REASON.startswith("net::")
