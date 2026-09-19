"""Tests for crawler.Mapper (orchestrator, without launching a real browser)."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from crawler import Mapper
from crawler.navigation import NavigationHandler
from crawler.navigation.dom_hasher import DOMHasher
from crawler.network import NetworkInterceptor


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
