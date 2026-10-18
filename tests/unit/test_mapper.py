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

        assert calls == ["route", "route", "new_page"]
        assert [c.args[1] for c in context.route.call_args_list] == [
            m.write_guard._handle_route, m.navigation_guard._handle_route]
        assert browser.new_context.call_args.kwargs["service_workers"] == "block"
        assert m._capture.write_guard is m.write_guard

    async def test_allow_policy_leaves_writes_unguarded(self, make_config):
        starter, browser, context, calls = _fake_playwright()
        m = Mapper(make_config(write_policy="allow"))
        with patch("crawler.mapper.async_playwright", return_value=starter):
            await m.initialize()

        # Off-site navigations are still guarded whatever the write policy.
        assert calls == ["route", "new_page"]
        assert context.route.call_args.args[1] == m.navigation_guard._handle_route
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

    async def test_off_site_navigation_is_allowed_only_while_logging_in(self, make_config, mock_request):
        from config_loader import LoginConfig
        cfg = make_config()
        cfg.login = LoginConfig(login_url="http://x/login", username="u", password="p")
        m = Mapper(cfg)
        page = MagicMock()
        page.url = "http://x/login"
        # An SSO hop through a host that is neither the app nor the login URL.
        hop = mock_request(url="https://federation.example.com/saml", resource_type="document",
                           navigation=True, frame=MagicMock(parent_frame=None))
        allowed_during_login = []

        async def login(*args):
            allowed_during_login.append(m.navigation_guard.is_allowed(hop))

        with patch("crawler.mapper.perform_login", AsyncMock(side_effect=login)):
            await m._ensure_authenticated(page)

        assert allowed_during_login == [True]
        assert m.navigation_guard.is_allowed(hop) is False


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


def _tab(url):
    tab = MagicMock()
    tab.url = url
    tab.close = AsyncMock()
    tab.wait_for_event = AsyncMock()
    return tab


class TestNewTabs:
    async def test_initialize_handles_tabs_after_the_capture_sees_them(self, make_config):
        starter, browser, context, calls = _fake_playwright()
        m = Mapper(make_config())
        with patch("crawler.mapper.async_playwright", return_value=starter):
            await m.initialize()

        handlers = [c.args[1] for c in context.on.call_args_list if c.args[0] == "page"]
        assert handlers == [m._capture._setup_page, m._handle_new_tab]

    async def test_off_site_tab_is_closed_and_not_crawled(self, make_config):
        m = Mapper(make_config())
        tab = _tab("https://github.com/org/repo")
        await m._handle_new_tab(tab)
        tab.close.assert_awaited_once()
        tab.wait_for_event.assert_not_called()
        assert m._opened_tabs == []

    async def test_app_tab_is_closed_and_queued_at_its_openers_depth(self, make_config):
        m = Mapper(make_config())
        m._exploring_depth = 1
        tab = _tab("http://localhost:8080/invoice/7")
        await m._handle_new_tab(tab)
        tab.close.assert_awaited_once()
        assert m._opened_tabs == [("http://localhost:8080/invoice/7", 1)]

    async def test_excluded_app_tab_is_not_queued(self, make_config):
        m = Mapper(make_config())
        tab = _tab("http://localhost:8080/logout")
        await m._handle_new_tab(tab)
        tab.close.assert_awaited_once()
        assert m._opened_tabs == []

    async def test_blank_tab_is_judged_by_its_first_navigation(self, make_config):
        m = Mapper(make_config())
        tab = _tab("about:blank")

        async def navigate(*args, **kwargs):
            tab.url = "http://localhost:8080/preview"

        tab.wait_for_event.side_effect = navigate
        await m._handle_new_tab(tab)
        assert tab.wait_for_event.call_args.args == ("framenavigated",)
        assert m._opened_tabs == [("http://localhost:8080/preview", 0)]
        tab.close.assert_awaited_once()

    async def test_tab_that_never_navigates_is_closed(self, make_config):
        m = Mapper(make_config())
        tab = _tab("about:blank")
        tab.wait_for_event.side_effect = TimeoutError("Timeout 10000ms exceeded")
        await m._handle_new_tab(tab)
        tab.close.assert_awaited_once()
        assert m._opened_tabs == []

    async def test_main_tab_is_never_closed(self, make_config):
        m = Mapper(make_config())
        m.page = _tab("https://github.com/org/repo")
        await m._handle_new_tab(m.page)
        m.page.close.assert_not_called()

    async def test_links_visit_the_tabs_this_depth_opened(self, make_config, mock_page):
        m = Mapper(make_config(max_depth=3))
        m._opened_tabs = [("http://localhost:8080/invoice/7", 1), ("http://localhost:8080/deeper", 2)]
        m.navigator.navigate_to = AsyncMock(return_value=False)
        page = mock_page("http://localhost:8080/orders")
        page.eval_on_selector_all = AsyncMock(return_value=[])

        await m._follow_links_on_page(page, 1)

        m.navigator.navigate_to.assert_awaited_once_with(page, "http://localhost:8080/invoice/7", 2)
        assert m._opened_tabs == [("http://localhost:8080/deeper", 2)]

    async def test_depth_is_restored_after_exploring_a_child(self, make_config, mock_page):
        m = Mapper(make_config(max_depth=3))
        m._explore_page = AsyncMock(side_effect=lambda page, depth: setattr(m, "_exploring_depth", depth))
        m.dom_hasher.get_dom_hash = AsyncMock(return_value=None)

        await m._maybe_explore_new_url(mock_page(), "http://localhost:8080/child", 1)

        m._explore_page.assert_awaited_once()
        assert m._exploring_depth == 1

    async def test_tab_the_navigation_guard_blocked_is_closed(self, make_config):
        # The guard gives a blocked new tab an error page so it surfaces here.
        m = Mapper(make_config())
        tab = _tab("chrome-error://chromewebdata/")
        await m._handle_new_tab(tab)
        tab.wait_for_event.assert_not_called()
        tab.close.assert_awaited_once()
        assert m._opened_tabs == []


class TestPopupElements:
    @staticmethod
    def _popup_link(href):
        el = AsyncMock()
        el.is_visible = AsyncMock(return_value=True)
        el.text_content = AsyncMock(return_value="Docs")
        el.get_attribute = AsyncMock(return_value=None)
        el.evaluate = AsyncMock(return_value=href)
        return el

    async def test_off_site_link_in_a_popup_is_not_clicked(self, make_config, mock_page):
        m = Mapper(make_config())
        el = self._popup_link("https://docs.example.com/help")
        await m._click_popup_element(mock_page(), el, "http://localhost:8080/", 0)
        el.click.assert_not_called()

    async def test_app_link_in_a_popup_is_clicked(self, make_config, mock_page):
        m = Mapper(make_config())
        el = self._popup_link("http://localhost:8080/settings")
        await m._click_popup_element(mock_page(), el, "http://localhost:8080/", 0)
        el.click.assert_awaited_once()


class TestDepthLimit:
    async def test_click_target_past_max_depth_is_left_unvisited(self, make_config, mock_page):
        # A shallower page that links to it must still be able to explore it.
        m = Mapper(make_config(max_depth=2))
        m._explore_page = AsyncMock()
        m.dom_hasher.get_dom_hash = AsyncMock(return_value="h1")

        await m._maybe_explore_new_url(mock_page(), "http://localhost:8080/contact", 1)

        m._explore_page.assert_not_called()
        assert "http://localhost:8080/contact" not in m.navigator.visited_urls
        assert not m.dom_hasher.is_dom_seen("h1")

    async def test_click_target_within_max_depth_is_explored(self, make_config, mock_page):
        m = Mapper(make_config(max_depth=2))
        m._explore_page = AsyncMock()
        m.dom_hasher.get_dom_hash = AsyncMock(return_value="h1")

        await m._maybe_explore_new_url(mock_page(), "http://localhost:8080/contact", 0)

        m._explore_page.assert_awaited_once()
        assert "http://localhost:8080/contact" in m.navigator.visited_urls

    async def test_links_are_not_loaded_when_their_pages_would_be_too_deep(self, make_config, mock_page):
        m = Mapper(make_config(max_depth=2))
        m.navigator.navigate_to = AsyncMock()
        page = mock_page("http://localhost:8080/privacy")
        page.eval_on_selector_all = AsyncMock(return_value=["http://localhost:8080/contact"])

        await m._follow_links_on_page(page, 1)

        m.navigator.navigate_to.assert_not_called()

    async def test_links_one_level_below_max_depth_are_followed(self, make_config, mock_page):
        m = Mapper(make_config(max_depth=2))
        m.navigator.navigate_to = AsyncMock(return_value=False)
        page = mock_page("http://localhost:8080/")
        page.eval_on_selector_all = AsyncMock(return_value=["http://localhost:8080/contact"])

        await m._follow_links_on_page(page, 0)

        m.navigator.navigate_to.assert_awaited_once_with(page, "http://localhost:8080/contact", 1)
