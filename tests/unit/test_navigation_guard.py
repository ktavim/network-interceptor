"""Tests for crawler.network.navigation_guard."""
import pytest
from unittest.mock import AsyncMock, MagicMock, PropertyMock

from config_loader import LoginConfig
from crawler.network.navigation_guard import NavigationGuard


@pytest.fixture
def guard(make_config):
    return NavigationGuard(make_config())


@pytest.fixture
def navigation(mock_request):
    """A top-level navigation request, as a click or script in the main tab makes."""
    def _make(url, method="GET"):
        return mock_request(method=method, url=url, resource_type="document",
                            navigation=True, frame=MagicMock(parent_frame=None))
    return _make


@pytest.fixture
def new_tab_navigation(mock_request):
    """The first navigation of a tab that doesn't exist yet: Playwright has no frame for it."""
    def _make(url):
        req = mock_request(url=url, resource_type="document", navigation=True)
        type(req).frame = PropertyMock(side_effect=Exception(
            "Frame for this navigation request is not available"))
        return req
    return _make


class TestIsAllowed:
    def test_app_navigation_passes(self, guard, navigation):
        assert guard.is_allowed(navigation("http://localhost:8080/orders")) is True

    @pytest.mark.parametrize("url", [
        "https://github.com/org/repo",
        "https://localhost:8080/orders",  # another scheme is another listener
        "http://localhost:9090/orders",
    ])
    def test_off_site_navigation_is_blocked(self, guard, navigation, url):
        assert guard.is_allowed(navigation(url)) is False

    def test_off_site_form_post_is_blocked(self, guard, navigation):
        assert guard.is_allowed(navigation("https://pay.example.com/checkout", method="POST")) is False

    def test_off_site_new_tab_is_blocked(self, guard, new_tab_navigation):
        assert guard.is_allowed(new_tab_navigation("https://github.com/org/repo")) is False

    def test_app_new_tab_passes(self, guard, new_tab_navigation):
        assert guard.is_allowed(new_tab_navigation("http://localhost:8080/invoice/7")) is True

    def test_iframe_navigation_passes(self, guard, mock_request):
        # An embedded widget is part of the app page that embeds it.
        req = mock_request(url="https://js.stripe.com/v3/elements", resource_type="document",
                           navigation=True, frame=MagicMock(parent_frame=MagicMock()))
        assert guard.is_allowed(req) is True

    def test_subresources_pass(self, guard, mock_request):
        assert guard.is_allowed(mock_request(url="https://cdn.example.com/app.js")) is True

    @pytest.mark.parametrize("url", ["blob:http://localhost:8080/abc", "data:text/html,hi", "about:blank"])
    def test_non_web_schemes_pass(self, guard, navigation, url):
        assert guard.is_allowed(navigation(url)) is True

    def test_login_origin_passes(self, make_config, navigation):
        # An expired session must still be able to reach its IdP.
        cfg = make_config(login=LoginConfig(
            login_url="https://sso.example.com/realms/corp", username="u", password="p"))
        guard = NavigationGuard(cfg)
        assert guard.is_allowed(navigation("https://sso.example.com/authorize?client_id=x")) is True
        assert guard.is_allowed(navigation("https://other.example.com/")) is False

    def test_anything_passes_while_offsite_is_allowed(self, guard, navigation):
        req = navigation("https://federation.example.com/saml")
        with guard.allow_offsite():
            assert guard.is_allowed(req) is True
        assert guard.is_allowed(req) is False

    def test_allow_offsite_restores_on_error(self, guard, navigation):
        with pytest.raises(RuntimeError):
            with guard.allow_offsite():
                raise RuntimeError("login failed")
        assert guard.is_allowed(navigation("https://github.com/")) is False

    def test_nested_allow_offsite_keeps_outer_window(self, guard, navigation):
        req = navigation("https://github.com/")
        with guard.allow_offsite():
            with guard.allow_offsite():
                pass
            assert guard.is_allowed(req) is True


class TestAttach:
    async def test_routes_every_request(self, guard):
        context = MagicMock()
        context.route = AsyncMock()
        await guard.attach(context)
        context.route.assert_awaited_once_with("**/*", guard._handle_route)


class TestHandleRoute:
    @staticmethod
    def _route(request):
        route = MagicMock()
        route.request = request
        route.fallback = AsyncMock()
        route.abort = AsyncMock()
        return route

    async def test_allowed_request_falls_through(self, guard, navigation):
        route = self._route(navigation("http://localhost:8080/orders"))
        await guard._handle_route(route)
        route.fallback.assert_awaited_once()
        route.abort.assert_not_called()
        assert guard.blocked_count == 0

    async def test_main_tab_navigation_is_cancelled_in_place(self, guard, navigation):
        # "aborted" leaves the tab on the app page, with no error page to go back from.
        route = self._route(navigation("https://github.com/org/repo"))
        await guard._handle_route(route)
        route.abort.assert_awaited_once_with("aborted")
        route.fallback.assert_not_called()
        assert guard.blocked_count == 1

    async def test_new_tab_navigation_gets_an_error_page(self, guard, new_tab_navigation):
        # A new tab cancelled with "aborted" never reaches Playwright and can't be closed.
        route = self._route(new_tab_navigation("https://github.com/org/repo"))
        await guard._handle_route(route)
        route.abort.assert_awaited_once_with("blockedbyclient")

    async def test_log_strips_the_query(self, guard, navigation, caplog):
        route = self._route(navigation("https://github.com/login?return_to=secret"))
        with caplog.at_level("INFO", logger="crawler.network.navigation_guard"):
            await guard._handle_route(route)
        assert "off-site navigation to https://github.com/login" in caplog.text
        assert "secret" not in caplog.text
