"""Shared test fixtures."""
import sys
import os
import pytest
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config_loader import Config, FormConfig


@pytest.fixture
def make_config():
    """Factory fixture that creates Config objects with sensible test defaults."""
    def _make_config(**overrides):
        defaults = {
            "start_url": "http://localhost:8080",
            "max_depth": 2,
            "max_clicks_per_page": 10,
            "wait_timeout": 10000,
            "network_idle_timeout": 500,
            "form_filling": FormConfig(),
            "exclude_patterns": ["logout", "delete", "remove"],
        }
        defaults.update(overrides)
        return Config(**defaults)
    return _make_config


@pytest.fixture
def mock_element():
    """Factory that creates mock Playwright elements with configurable attributes."""
    def _mock_element(text="", href="", classes="", element_id="", aria_label="",
                      input_type="", name="", evaluate_result=False, placeholder="",
                      minlength=None, pattern=None, required=None, value=None):
        el = AsyncMock()
        el.text_content = AsyncMock(return_value=text)
        attr_map = {
            "href": href or None,
            "class": classes or None,
            "id": element_id or None,
            "aria-label": aria_label or None,
            "type": input_type or None,
            "name": name or None,
            "placeholder": placeholder or None,
            "minlength": minlength,
            "pattern": pattern,
            "required": required,
            "value": value,
        }
        el.get_attribute = AsyncMock(side_effect=lambda attr: attr_map.get(attr))
        el.evaluate = AsyncMock(return_value=evaluate_result)
        return el
    return _mock_element


@pytest.fixture
def mock_page():
    """Factory for a minimally useful mock Playwright Page."""
    def _mock_page(url="http://localhost:8080/"):
        page = AsyncMock()
        page.url = url
        page.evaluate = AsyncMock(return_value="")
        page.query_selector_all = AsyncMock(return_value=[])
        page.locator = MagicMock()
        page.keyboard = AsyncMock()
        page.mouse = AsyncMock()
        page.wait_for_timeout = AsyncMock()
        page.wait_for_load_state = AsyncMock()
        page.wait_for_selector = AsyncMock()
        page.wait_for_url = AsyncMock()
        page.goto = AsyncMock()
        page.fill = AsyncMock()
        page.click = AsyncMock()
        page.dispatch_event = AsyncMock()
        page.on = MagicMock()
        return page
    return _mock_page


@pytest.fixture
def mock_request():
    """Factory for a mock Playwright Request."""
    def _mock_request(method="GET", url="http://api.example.com/v1/test",
                      headers=None, post_data=None, resource_type="fetch"):
        req = MagicMock()
        req.method = method
        req.url = url
        req.headers = headers or {}
        req.post_data = post_data
        req.resource_type = resource_type
        return req
    return _mock_request


@pytest.fixture
def mock_response():
    """Factory for a mock Playwright Response."""
    def _mock_response(status=200, headers=None):
        resp = MagicMock()
        resp.status = status
        resp.headers = headers or {}
        return resp
    return _mock_response
