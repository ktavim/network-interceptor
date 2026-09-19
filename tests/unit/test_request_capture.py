"""Tests for crawler.network.request_capture.RequestCapture."""
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


class TestOnRequest:
    async def test_skips_internal_url(self, capture, interceptor, mock_request):
        req = mock_request(url="http://localhost:8080/page")
        await capture._on_request(req)
        assert capture.pending_requests == {}

    async def test_captures_external_url(self, capture, mock_request):
        req = mock_request(url="http://api.example.com/v1")
        await capture._on_request(req)
        assert ("GET", "http://api.example.com/v1") in capture.pending_requests

    async def test_does_not_duplicate_pending(self, capture, mock_request):
        req = mock_request(url="http://api.example.com/v1")
        await capture._on_request(req)
        await capture._on_request(req)
        assert len(capture.pending_requests) == 1


class TestOnResponse:
    async def test_skips_internal(self, capture, interceptor):
        req = MagicMock()
        req.url = "http://localhost:8080/x"
        resp = MagicMock()
        resp.request = req
        await capture._on_response(resp)
        assert interceptor.requests == []

    async def test_captures_and_removes_pending(self, capture, interceptor, mock_request, mock_response):
        req = mock_request(url="http://api.example.com/v1")
        await capture._on_request(req)
        resp = mock_response(200)
        resp.request = req
        await capture._on_response(resp)
        assert len(interceptor.requests) == 1
        assert ("GET", "http://api.example.com/v1") in capture.captured_keys
        assert ("GET", "http://api.example.com/v1") not in capture.pending_requests

    async def test_skips_already_captured(self, capture, interceptor, mock_request, mock_response):
        capture.captured_keys.add(("GET", "http://api.example.com/v1"))
        req = mock_request(url="http://api.example.com/v1")
        resp = mock_response(200)
        resp.request = req
        await capture._on_response(resp)
        assert interceptor.requests == []


class TestOnRequestFailed:
    async def test_records_failure(self, capture, interceptor, mock_request):
        req = mock_request(url="http://api.example.com/v1")
        await capture._on_request_failed(req)
        assert len(interceptor.requests) == 1
        assert interceptor.requests[0]["status"] == 0
        assert interceptor.requests[0]["response_error"] == "Request failed"

    async def test_skips_internal(self, capture, interceptor, mock_request):
        req = mock_request(url="http://localhost:8080/x")
        await capture._on_request_failed(req)
        assert interceptor.requests == []
