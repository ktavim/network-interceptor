"""Tests for crawler.navigation.NavigationHandler (URL/state handling & delegation)."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from crawler.navigation import NavigationHandler
from crawler.navigation.dom_hasher import DOMHasher


class TestShouldFollowUrl:
    @pytest.fixture
    def handler(self, make_config):
        return NavigationHandler(make_config(start_url="http://localhost:8080"))

    def test_same_domain(self, handler):
        assert handler._should_follow_url("http://localhost:8080/page2") is True

    def test_same_domain_with_path(self, handler):
        assert handler._should_follow_url("http://localhost:8080/a/b/c") is True

    def test_different_domain(self, handler):
        assert handler._should_follow_url("http://other.com/page") is False

    def test_different_port(self, handler):
        assert handler._should_follow_url("http://localhost:9090/page") is False

    def test_different_scheme(self, handler):
        assert handler._should_follow_url("https://localhost:8080/page") is False

    def test_javascript_url(self, handler):
        assert handler._should_follow_url("javascript:void(0)") is False

    def test_mailto_url(self, handler):
        assert handler._should_follow_url("mailto:a@b.com") is False

    def test_empty_string(self, handler):
        assert handler._should_follow_url("") is False

    def test_none(self, handler):
        assert handler._should_follow_url(None) is False

    def test_same_domain_with_query(self, handler):
        assert handler._should_follow_url("http://localhost:8080/page?q=1") is True

    def test_same_domain_with_fragment(self, handler):
        assert handler._should_follow_url("http://localhost:8080/page#section") is True

    def test_tel_url(self, handler):
        assert handler._should_follow_url("tel:+1234567890") is False

    def test_ftp_url(self, handler):
        assert handler._should_follow_url("ftp://localhost:8080/file") is False

    def test_start_url_with_path(self, make_config):
        h = NavigationHandler(make_config(start_url="http://example.com/app"))
        assert h._should_follow_url("http://example.com/other") is True
        assert h._should_follow_url("http://other.com/app") is False

    def test_explicit_default_port_is_same_origin(self, make_config):
        h = NavigationHandler(make_config(start_url="https://example.com/app"))
        assert h._should_follow_url("https://example.com:443/other") is True
        assert h._should_follow_url("https://EXAMPLE.com/other") is True
        assert h._should_follow_url("https://example.com:8443/other") is False


class TestDelegatesToElementClassifier:
    async def test_is_destructive_action_delegates(self, make_config, mock_element):
        handler = NavigationHandler(make_config(exclude_patterns=["logout"]))
        assert await handler.is_destructive_action(mock_element(text="Logout")) is True
        assert await handler.is_destructive_action(mock_element(text="Dashboard")) is False

    async def test_explicit_text_param(self, make_config, mock_element):
        handler = NavigationHandler(make_config())
        assert await handler.is_destructive_action(mock_element(text="Submit"), text="logout") is True


class TestDOMHasherDelegation:
    def test_visited_dom_hashes_uses_shared_hasher(self, make_config):
        shared = DOMHasher()
        handler = NavigationHandler(make_config(), dom_hasher=shared)
        shared.mark_dom_seen("abc")
        assert "abc" in handler.visited_dom_hashes

    def test_visited_dom_hashes_setter(self, make_config):
        handler = NavigationHandler(make_config())
        handler.visited_dom_hashes = {"x", "y"}
        assert handler.dom_hasher.visited_dom_hashes == {"x", "y"}

    def test_visited_overlay_hashes_setter(self, make_config):
        handler = NavigationHandler(make_config())
        handler.visited_overlay_hashes = {"ov1"}
        assert handler.dom_hasher.visited_overlay_hashes == {"ov1"}

    def test_creates_own_hasher_when_none_passed(self, make_config):
        handler = NavigationHandler(make_config())
        assert isinstance(handler.dom_hasher, DOMHasher)


class TestNavigationHandlerState:
    def test_initial_state(self, make_config):
        handler = NavigationHandler(make_config())
        assert handler.visited_urls == set()
        assert handler.visited_dom_hashes == set()
        assert handler.current_depth == 0
        assert handler.clicks_on_current_page == 0
        assert handler.visited_overlay_hashes == set()
        assert handler.page_overlay_blocked is False

    def test_reset_page_counters(self, make_config):
        handler = NavigationHandler(make_config())
        handler.clicks_on_current_page = 15
        handler.reset_page_counters()
        assert handler.clicks_on_current_page == 0

    def test_can_continue_navigation_under_limit(self, make_config):
        handler = NavigationHandler(make_config(max_depth=3))
        handler.current_depth = 2
        assert handler.can_continue_navigation() is True

    def test_can_continue_navigation_at_limit(self, make_config):
        handler = NavigationHandler(make_config(max_depth=3))
        handler.current_depth = 3
        assert handler.can_continue_navigation() is False

    def test_can_continue_navigation_over_limit(self, make_config):
        handler = NavigationHandler(make_config(max_depth=3))
        handler.current_depth = 5
        assert handler.can_continue_navigation() is False


class TestNavigateTo:
    async def test_rejects_over_max_depth(self, make_config, mock_page):
        handler = NavigationHandler(make_config(max_depth=2))
        assert await handler.navigate_to(mock_page(), "http://localhost:8080/x", depth=3) is False

    async def test_rejects_already_visited(self, make_config, mock_page):
        handler = NavigationHandler(make_config())
        handler.visited_urls.add("http://localhost:8080/x")
        assert await handler.navigate_to(mock_page(), "http://localhost:8080/x") is False

    async def test_rejects_external(self, make_config, mock_page):
        handler = NavigationHandler(make_config())
        assert await handler.navigate_to(mock_page(), "http://other.com/x") is False

    async def test_success_marks_visited_and_hash(self, make_config, mock_page):
        handler = NavigationHandler(make_config())
        page = mock_page()
        with patch.object(handler.dom_hasher, "get_dom_hash", AsyncMock(return_value="h1")):
            ok = await handler.navigate_to(page, "http://localhost:8080/new", depth=1)
        assert ok is True
        assert "http://localhost:8080/new" in handler.visited_urls
        assert handler.dom_hasher.is_dom_seen("h1")
        assert handler.current_depth == 1
        assert handler.clicks_on_current_page == 0

    async def test_skips_duplicate_dom(self, make_config, mock_page):
        handler = NavigationHandler(make_config())
        handler.dom_hasher.mark_dom_seen("h1")
        page = mock_page()
        with patch.object(handler.dom_hasher, "get_dom_hash", AsyncMock(return_value="h1")):
            assert await handler.navigate_to(page, "http://localhost:8080/dup") is False

    async def test_goto_exception_returns_false(self, make_config, mock_page):
        handler = NavigationHandler(make_config())
        page = mock_page()
        page.goto.side_effect = Exception("boom")
        assert await handler.navigate_to(page, "http://localhost:8080/err") is False


class TestClickElement:
    async def test_respects_max_clicks(self, make_config, mock_page):
        handler = NavigationHandler(make_config(max_clicks_per_page=2))
        handler.clicks_on_current_page = 2
        el = AsyncMock()
        assert await handler.click_element(mock_page(), el) is False

    async def test_skips_invisible(self, make_config, mock_page):
        handler = NavigationHandler(make_config())
        el = AsyncMock()
        el.is_visible = AsyncMock(return_value=False)
        assert await handler.click_element(mock_page(), el) is False
        assert handler.clicks_on_current_page == 0

    async def test_successful_click(self, make_config, mock_page):
        handler = NavigationHandler(make_config())
        el = AsyncMock()
        el.is_visible = AsyncMock(return_value=True)
        el.scroll_into_view_if_needed = AsyncMock()
        el.click = AsyncMock()
        page = mock_page()
        assert await handler.click_element(page, el) is True
        assert handler.clicks_on_current_page == 1


class TestOverlayBlockGuard:
    async def test_click_skipped_when_blocked(self, make_config, mock_page):
        handler = NavigationHandler(make_config())
        handler.page_overlay_blocked = True
        el = AsyncMock()
        el.is_visible = AsyncMock(return_value=True)
        assert await handler.click_element(mock_page(), el) is False
        el.click.assert_not_called()

    def test_reset_overlay_state(self, make_config):
        handler = NavigationHandler(make_config())
        handler.page_overlay_blocked = True
        handler.reset_overlay_state()
        assert handler.page_overlay_blocked is False

    async def test_navigate_to_clears_blocked(self, make_config, mock_page):
        handler = NavigationHandler(make_config())
        handler.page_overlay_blocked = True
        page = mock_page()
        with patch.object(handler.dom_hasher, "get_dom_hash", AsyncMock(return_value="h9")):
            await handler.navigate_to(page, "http://localhost:8080/fresh", depth=1)
        assert handler.page_overlay_blocked is False

    async def test_recover_marks_blocked_when_overlay_persists(self, make_config, mock_page):
        """If overlay.handle() runs but the element still can't be clicked, the
        page is marked blocked (so siblings short-circuit) and the error re-raised."""
        handler = NavigationHandler(make_config())
        page = mock_page()
        element = AsyncMock()
        element.click = AsyncMock(side_effect=Exception("retry still intercepts pointer events"))
        handler._has_visible_modal = AsyncMock(return_value=True)
        handler.overlay.handle = AsyncMock()

        click_err = Exception(
            '<div id="select2-drop-mask" class="select2-drop-mask"></div> intercepts pointer events'
        )
        with pytest.raises(Exception):
            await handler._recover_from_click_error(page, element, click_err)

        handler.overlay.handle.assert_called_once()
        assert handler.page_overlay_blocked is True

    async def test_recover_not_blocked_when_overlay_cleared(self, make_config, mock_page):
        handler = NavigationHandler(make_config())
        page = mock_page()
        element = AsyncMock()
        element.click = AsyncMock()  # retry after handle() succeeds
        handler._has_visible_modal = AsyncMock(return_value=True)
        handler.overlay.handle = AsyncMock()

        click_err = Exception('<div class="blocker"></div> intercepts pointer events')
        await handler._recover_from_click_error(page, element, click_err)

        handler.overlay.handle.assert_called_once()
        element.click.assert_called_once_with(timeout=3000)
        assert handler.page_overlay_blocked is False
