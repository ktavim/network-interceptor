"""Tests for crawler.network.request_capture.RequestCapture."""
import logging

import pytest
from unittest.mock import AsyncMock, MagicMock

from crawler.network import NetworkInterceptor, RequestCapture


@pytest.fixture
def interceptor():
    return NetworkInterceptor()


@pytest.fixture
def capture(interceptor):
    return RequestCapture(interceptor, "http://localhost:8080")


class TestIsExternalUrl:
    def test_same_host_is_internal(self, capture):
        assert capture._is_external_url("http://localhost:8080/path") is False

    def test_different_host_is_external(self, capture):
        assert capture._is_external_url("http://api.example.com/x") is True

    def test_different_port_is_external(self, capture):
        assert capture._is_external_url("http://localhost:9090/x") is True

    def test_different_scheme_is_external(self, capture):
        # Same host and port over https is another listener, not the scanned app.
        assert capture._is_external_url("https://localhost:8080/x") is True

    def test_explicit_default_port_is_internal(self, interceptor):
        capture = RequestCapture(interceptor, "https://app.internal")
        assert capture._is_external_url("https://app.internal:443/x") is False
        assert capture._is_external_url("https://APP.internal/x") is False

    def test_invalid_url_is_external(self, capture):
        # A malformed string has no origin at all, so it can't be the start origin.
        assert capture._is_external_url("not a url") is True


def _registered_handler(page, event):
    return next(call.args[1] for call in page.on.call_args_list if call.args[0] == event)


class TestAttach:
    def test_registers_handlers_on_page_and_context(self, capture):
        page = MagicMock()
        context = MagicMock()
        capture.attach(page, context)
        assert page.on.call_count == 4  # request, response, requestfailed, requestfinished
        events = {call.args[0] for call in page.on.call_args_list}
        assert events == {"request", "response", "requestfailed", "requestfinished"}
        context.on.assert_called_once_with("page", capture._setup_page)

    def test_setup_new_page_opened_in_context(self, capture):
        page = MagicMock()
        context = MagicMock()
        capture.attach(page, context)
        # Simulate new page from context
        new_page = MagicMock()
        capture._setup_page(new_page)
        assert new_page.on.call_count == 4

    async def test_handlers_read_the_page_they_listen_on(self, capture, mock_page, mock_request):
        # Two pages share one capture (main page plus one opened in the context).
        # A request seen on the second page is stamped with that page's URL, not
        # the first one's.
        main = mock_page("http://localhost:8080/home")
        opened = mock_page("http://localhost:8080/popup")
        capture._setup_page(main)
        capture._setup_page(opened)

        await _registered_handler(opened, "request")(mock_request(url="http://api.example.com/v1"))

        key = ("GET", "http://api.example.com/v1")
        assert capture.pending_requests[key]["source_url"] == "http://localhost:8080/popup"


class TestOnRequest:
    async def test_skips_internal_url(self, capture, interceptor, mock_request, mock_page):
        req = mock_request(url="http://localhost:8080/page")
        await capture._on_request(req, page=mock_page())
        assert capture.pending_requests == {}

    async def test_captures_external_url(self, capture, mock_request, mock_page):
        req = mock_request(url="http://api.example.com/v1")
        await capture._on_request(req, page=mock_page())
        assert ("GET", "http://api.example.com/v1") in capture.pending_requests

    async def test_does_not_duplicate_pending(self, capture, mock_request, mock_page):
        req = mock_request(url="http://api.example.com/v1")
        await capture._on_request(req, page=mock_page())
        await capture._on_request(req, page=mock_page())
        assert len(capture.pending_requests) == 1

    async def test_stamps_the_page_url(self, capture, mock_request, mock_page):
        req = mock_request(url="http://api.example.com/v1")
        await capture._on_request(req, page=mock_page("http://localhost:8080/settings"))
        entry = capture.pending_requests[("GET", "http://api.example.com/v1")]
        assert entry["source_url"] == "http://localhost:8080/settings"

    async def test_page_url_is_read_when_the_request_fires(
        self, capture, interceptor, mock_request, mock_response, mock_page
    ):
        # The stamp is the page at request time. A navigation that commits
        # before the response lands must not re-attribute the request.
        page = mock_page("http://localhost:8080/home")
        req = mock_request(url="http://api.example.com/v1")
        await capture._on_request(req, page=page)

        page.url = "http://localhost:8080/next"
        resp = mock_response(200)
        resp.request = req
        await capture._on_response(resp, page=page)

        assert interceptor.requests[0]["source_url"] == "http://localhost:8080/home"


class TestOnResponse:
    async def test_skips_internal(self, capture, interceptor, mock_page):
        req = MagicMock()
        req.url = "http://localhost:8080/x"
        resp = MagicMock()
        resp.request = req
        await capture._on_response(resp, page=mock_page())
        assert interceptor.requests == []

    async def test_captures_and_removes_pending(self, capture, interceptor, mock_request, mock_response, mock_page):
        req = mock_request(url="http://api.example.com/v1")
        await capture._on_request(req, page=mock_page())
        resp = mock_response(200)
        resp.request = req
        await capture._on_response(resp, page=mock_page())
        assert len(interceptor.requests) == 1
        assert ("GET", "http://api.example.com/v1") in capture.captured_keys
        assert ("GET", "http://api.example.com/v1") not in capture.pending_requests

    async def test_response_without_pending_stamps_current_page(
        self, capture, interceptor, mock_request, mock_response, mock_page
    ):
        # No request event was seen (listener attached mid-flight): the response
        # handler builds the record itself and stamps the page it is on now.
        req = mock_request(url="http://api.example.com/v1")
        resp = mock_response(200)
        resp.request = req
        await capture._on_response(resp, page=mock_page("http://localhost:8080/late"))
        assert interceptor.requests[0]["source_url"] == "http://localhost:8080/late"

    async def test_skips_already_captured(self, capture, interceptor, mock_request, mock_response, mock_page):
        capture.captured_keys.add(("GET", "http://api.example.com/v1"))
        req = mock_request(url="http://api.example.com/v1")
        resp = mock_response(200)
        resp.request = req
        await capture._on_response(resp, page=mock_page())
        assert interceptor.requests == []


class TestOnRequestFailed:
    async def test_records_failure(self, capture, interceptor, mock_request, mock_page, caplog):
        req = mock_request(url="http://api.example.com/v1")
        with caplog.at_level(logging.DEBUG, logger="crawler.network.request_capture"):
            await capture._on_request_failed(req, page=mock_page("http://localhost:8080/home"))
        assert len(interceptor.requests) == 1
        assert interceptor.requests[0]["status"] == 0
        assert interceptor.requests[0]["source_url"] == "http://localhost:8080/home"
        assert "Request failed for GET http://api.example.com/v1" in caplog.text

    async def test_skips_internal(self, capture, interceptor, mock_request, mock_page):
        req = mock_request(url="http://localhost:8080/x")
        await capture._on_request_failed(req, page=mock_page())
        assert interceptor.requests == []
