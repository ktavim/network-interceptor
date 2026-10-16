"""Tests for crawler.Mapper (orchestrator, without launching a real browser)."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from crawler import Mapper
from crawler.navigation import NavigationHandler
from crawler.navigation.dom_hasher import DOMHasher
from crawler.network import NetworkInterceptor


@pytest.fixture(autouse=True)
def no_dns():
    # map_website resolves every origin host; unit tests must not hit DNS.
    with patch("crawler.mapper.resolve_hosts",
               AsyncMock(side_effect=lambda hosts: {h: [f"ip-of-{h}"] for h in hosts})):
        yield


class TestInit:
    def test_wires_components(self, make_config):
        cfg = make_config()
        m = Mapper(cfg)
        assert m.config is cfg
        assert isinstance(m.interceptor, NetworkInterceptor)
        assert isinstance(m.dom_hasher, DOMHasher)
        assert isinstance(m.navigator, NavigationHandler)
        assert m.navigator.dom_hasher is m.dom_hasher
        assert m.playwright is None
        assert m.browser is None
        assert m.page is None


def _fake_playwright():
    calls = []
    context = MagicMock()
    context.route = AsyncMock(side_effect=lambda *a: calls.append("route"))
    context.new_page = AsyncMock(side_effect=lambda: calls.append("new_page") or MagicMock())
    browser = MagicMock()
    browser.new_context = AsyncMock(return_value=context)
    pw = MagicMock()
    pw.chromium.launch = AsyncMock(return_value=browser)
    starter = MagicMock()
    starter.start = AsyncMock(return_value=pw)
    return starter, browser, context, calls


class TestInitialize:
    async def test_guard_is_routed_before_the_first_page(self, make_config):
        starter, browser, context, calls = _fake_playwright()
        m = Mapper(make_config())
        with patch("crawler.mapper.async_playwright", return_value=starter):
            await m.initialize()

        assert calls == ["route", "new_page"]
        assert browser.new_context.call_args.kwargs["service_workers"] == "block"
        assert m._capture.write_guard is m.write_guard

    async def test_allow_policy_leaves_the_context_unguarded(self, make_config):
        starter, browser, context, calls = _fake_playwright()
        m = Mapper(make_config(write_policy="allow"))
        with patch("crawler.mapper.async_playwright", return_value=starter):
            await m.initialize()

        assert calls == ["new_page"]
        assert "service_workers" not in browser.new_context.call_args.kwargs


class TestMapWebsite:
    async def test_returns_empty_when_navigation_fails(self, make_config):
        m = Mapper(make_config())
        m.page = MagicMock()
        m.navigator.navigate_to = AsyncMock(return_value=False)
        result = await m.map_website()
        assert result["external_services"] == []

    async def test_aggregates_interceptor_requests(self, make_config):
        m = Mapper(make_config())
        m.page = MagicMock()
        m.navigator.navigate_to = AsyncMock(return_value=True)
        m._ensure_authenticated = AsyncMock()
        m._explore_page = AsyncMock()
        m.interceptor.requests = [
            {"url": "http://api.example.com/x", "authentication": "bearer"},
            {"url": "https://api.example.com/x", "authentication": "bearer"},
            {"url": "http://other.com:8081/y", "authentication": "unauthenticated"},
        ]
        result = await m.map_website()
        origins = {(e["scheme"], e["host"], e["port"]) for e in result["external_services"]}
        assert origins == {
            ("http", "api.example.com", 80),
            ("https", "api.example.com", 443),
            ("http", "other.com", 8081),
        }
        assert {e["host"]: e["ips"] for e in result["external_services"]} == {
            "api.example.com": ["ip-of-api.example.com"],
            "other.com": ["ip-of-other.com"],
        }


class TestOriginEvents:
    @staticmethod
    def _recording_mapper(make_config):
        events = []
        m = Mapper(make_config(), on_event=lambda t, p: events.append((t, p)))
        m.interceptor.requests = [
            {"url": "http://api.example.com/x", "authentication": "basic"},
            {"url": "https://api.example.com/x", "authentication": "bearer"},
            {"url": "https://api.example.com:443/y", "authentication": "bearer"},
        ]
        return m, events

    async def test_page_visit_announces_each_origin_once(self, make_config):
        m, events = self._recording_mapper(make_config)
        await m._record_page_visit("http://localhost:8080/", 0)
        await m._record_page_visit("http://localhost:8080/next", 1)

        seen = [p for t, p in events if t == "external_service_seen"]
        assert sorted(seen, key=lambda p: p["port"]) == [
            {"scheme": "http", "host": "api.example.com", "port": 80},
            {"scheme": "https", "host": "api.example.com", "port": 443},
        ]
        # Two origins on one hostname are two services -- the same stat the
        # finished scan reports as external_services -- and a revisit adds none.
        progress = [p for t, p in events if t == "scan_progress"]
        assert [p["services"] for p in progress] == [2, 2]

    async def test_auth_detected_carries_the_origin(self, make_config):
        m, events = self._recording_mapper(make_config)
        m.page = MagicMock()
        m.navigator.navigate_to = AsyncMock(return_value=True)
        m._ensure_authenticated = AsyncMock()
        m._explore_page = AsyncMock()
        await m.map_website()

        detected = {(p["scheme"], p["host"], p["port"]): p["method"]
                    for t, p in events if t == "auth_detected"}
        assert detected == {
            ("http", "api.example.com", 80): "basic",
            ("https", "api.example.com", 443): "bearer",
        }


class TestEnsureAuthenticated:
    async def test_noop_when_no_login_config(self, make_config):
        m = Mapper(make_config())
        page = MagicMock()
        page.url = "http://x/home"
        # Should not raise; config.login is None
        await m._ensure_authenticated(page)

    async def test_noop_when_not_on_login_page(self, make_config):
        from config_loader import LoginConfig
        cfg = make_config()
        cfg.login = LoginConfig(login_url="http://x/login", username="u", password="p")
        m = Mapper(cfg)
        page = MagicMock()
        page.url = "http://x/dashboard"
        with patch("crawler.mapper.perform_login", AsyncMock()) as pl:
            await m._ensure_authenticated(page)
            pl.assert_not_called()

    async def test_performs_login_when_on_login_page(self, make_config):
        from config_loader import LoginConfig
        cfg = make_config()
        cfg.login = LoginConfig(login_url="http://x/login", username="u", password="p")
        m = Mapper(cfg)
        page = MagicMock()
        page.url = "http://x/login"
        with patch("crawler.mapper.perform_login", AsyncMock()) as pl:
            await m._ensure_authenticated(page)
            pl.assert_called_once_with(page, cfg.login, cfg.start_url)

    async def test_writes_are_allowed_only_while_logging_in(self, make_config, mock_request):
        from config_loader import LoginConfig
        cfg = make_config()
        cfg.login = LoginConfig(login_url="http://x/login", username="u", password="p")
        m = Mapper(cfg)
        page = MagicMock()
        page.url = "http://x/login"
        form_post = mock_request(method="POST", url="http://localhost:8080/api/items")
        allowed_during_login = []

        async def login(*args):
            allowed_during_login.append(m.write_guard.is_allowed(form_post))

        with patch("crawler.mapper.perform_login", AsyncMock(side_effect=login)):
            await m._ensure_authenticated(page)

        assert allowed_during_login == [True]
        assert m.write_guard.is_allowed(form_post) is False

    async def test_login_retry_also_runs_with_writes_allowed(self, make_config, mock_request, tmp_path):
        from config_loader import LoginConfig
        cfg = make_config()
        cfg.login = LoginConfig(login_url="http://x/login", username="u", password="p",
                                storage_state_path=str(tmp_path / "state.json"))
        m = Mapper(cfg)
        m._used_reused_storage = True
        page = MagicMock()
        page.url = "http://x/login"
        page.goto = AsyncMock()
        form_post = mock_request(method="POST", url="http://localhost:8080/api/items")
        allowed = []

        async def login(*args):
            allowed.append(m.write_guard.is_allowed(form_post))
            if len(allowed) == 1:
                raise RuntimeError("stale session")

        with patch("crawler.mapper.perform_login", AsyncMock(side_effect=login)):
            await m._ensure_authenticated(page)

        assert allowed == [True, True]
        assert m.write_guard.is_allowed(form_post) is False


class TestCleanup:
    async def test_closes_all_components(self, make_config):
        m = Mapper(make_config())
        m.page = AsyncMock()
        m.context = AsyncMock()
        m.browser = AsyncMock()
        m.playwright = AsyncMock()
        await m.cleanup()
        m.page.close.assert_called_once()
        m.context.close.assert_called_once()
        m.browser.close.assert_called_once()
        m.playwright.stop.assert_called_once()

    async def test_tolerates_none_attributes(self, make_config):
        m = Mapper(make_config())
        await m.cleanup()  # should not raise

    async def test_partial_cleanup(self, make_config):
        m = Mapper(make_config())
        m.page = AsyncMock()
        m.browser = AsyncMock()
        await m.cleanup()
        m.page.close.assert_called_once()
        m.browser.close.assert_called_once()

    async def test_failing_step_neither_raises_nor_skips_the_rest(self, make_config):
        # A browser that already died must not mask the cancel being unwound.
        m = Mapper(make_config())
        m.page = AsyncMock()
        m.page.close.side_effect = RuntimeError("Target closed")
        m.context = AsyncMock()
        m.browser = AsyncMock()
        m.playwright = AsyncMock()
        m.playwright.stop.side_effect = RuntimeError("driver gone")
        await m.cleanup()
        m.context.close.assert_called_once()
        m.browser.close.assert_called_once()
