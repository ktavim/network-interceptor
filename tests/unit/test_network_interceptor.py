"""Tests for crawler.network.NetworkInterceptor."""
import pytest
from unittest.mock import MagicMock

from crawler.network import NetworkInterceptor


@pytest.fixture
def interceptor():
    return NetworkInterceptor()


class TestGetPostData:
    async def test_json_body(self, interceptor, mock_request):
        req = mock_request("POST", post_data='{"k": "v"}', headers={"content-type": "application/json"})
        assert await interceptor._get_post_data(req) == {"k": "v"}

    async def test_form_urlencoded(self, interceptor, mock_request):
        req = mock_request("POST", post_data="u=a&p=b",
                           headers={"content-type": "application/x-www-form-urlencoded"})
        result = await interceptor._get_post_data(req)
        assert "u" in result and "p" in result

    async def test_form_multiple_values(self, interceptor, mock_request):
        req = mock_request("POST", post_data="t=a&t=b&t=c",
                           headers={"content-type": "application/x-www-form-urlencoded"})
        result = await interceptor._get_post_data(req)
        assert len(result["t"]) == 3

    async def test_raw_fallback(self, interceptor, mock_request):
        req = mock_request("POST", post_data="plain",
                           headers={"content-type": "text/plain"})
        assert await interceptor._get_post_data(req) == {"raw": "plain"}

    async def test_malformed_json_falls_to_raw(self, interceptor, mock_request):
        req = mock_request("POST", post_data="{bad", headers={"content-type": "application/json"})
        assert await interceptor._get_post_data(req) == {"raw": "{bad"}

    async def test_get_returns_none(self, interceptor, mock_request):
        assert await interceptor._get_post_data(mock_request("GET")) is None

    async def test_delete_returns_none(self, interceptor, mock_request):
        assert await interceptor._get_post_data(mock_request("DELETE", post_data='{"x":1}')) is None

    async def test_none_post_data(self, interceptor, mock_request):
        assert await interceptor._get_post_data(mock_request("POST", post_data=None)) is None

    async def test_empty_post_data(self, interceptor, mock_request):
        assert await interceptor._get_post_data(mock_request("POST", post_data="")) is None

    async def test_put_json(self, interceptor, mock_request):
        req = mock_request("PUT", post_data='{"u": true}', headers={"content-type": "application/json"})
        assert await interceptor._get_post_data(req) == {"u": True}

    async def test_patch_json(self, interceptor, mock_request):
        req = mock_request("PATCH", post_data='{"f": "n"}', headers={"content-type": "application/json"})
        assert await interceptor._get_post_data(req) == {"f": "n"}


class TestHandleRequest:
    async def test_returns_expected_keys(self, interceptor, mock_request):
        req = mock_request("GET", headers={"authorization": "Bearer abc"})
        interceptor.source_url = "http://example.com"
        result = await interceptor.handle_request(req)
        assert result["url"] == "http://api.example.com/v1/test"
        assert result["method"] == "GET"
        assert result["authentication"] == "bearer"
        assert result["source_url"] == "http://example.com"
        assert result["resource_type"] == "fetch"


class TestHandleResponse:
    async def test_200(self, interceptor, mock_response):
        req_data = {"url": "http://a.com", "authentication": "unauthenticated"}
        result = await interceptor.handle_response(req_data, mock_response(200))
        assert result["status"] == 200
        assert len(interceptor.requests) == 1

    async def test_401_basic(self, interceptor, mock_response):
        req_data = {"url": "http://a.com", "authentication": "unauthenticated"}
        result = await interceptor.handle_response(
            req_data, mock_response(401, {"www-authenticate": 'Basic realm="test"'})
        )
        assert result["authentication"] == "basic"

    async def test_401_bearer(self, interceptor, mock_response):
        req_data = {"url": "http://a.com", "authentication": "unauthenticated"}
        result = await interceptor.handle_response(
            req_data, mock_response(401, {"www-authenticate": 'Bearer realm="api"'})
        )
        assert result["authentication"] == "bearer"

    async def test_401_negotiate(self, interceptor, mock_response):
        req_data = {"url": "http://a.com", "authentication": "unauthenticated"}
        result = await interceptor.handle_response(
            req_data, mock_response(401, {"www-authenticate": "Negotiate"})
        )
        assert result["authentication"] == "negotiate"

    async def test_401_ntlm(self, interceptor, mock_response):
        # A bare "WWW-Authenticate: NTLM" challenge is labeled explicitly rather
        # than falling into the "other" bucket, so the raw authentication field
        # names the scheme honestly.
        req_data = {"url": "http://a.com", "authentication": "unauthenticated"}
        result = await interceptor.handle_response(
            req_data, mock_response(401, {"www-authenticate": "NTLM"})
        )
        assert result["authentication"] == "ntlm"

    async def test_401_other_scheme(self, interceptor, mock_response):
        req_data = {"url": "http://a.com", "authentication": "unauthenticated"}
        result = await interceptor.handle_response(
            req_data, mock_response(401, {"www-authenticate": 'Digest realm="t"'})
        )
        # A scheme we don't name specifically is tagged "other"; the raw challenge
        # is kept for evidence alongside it, not folded into the label.
        assert result["authentication"] == "other"
        assert result["auth_challenge"] == 'Digest realm="t"'

    async def test_401_without_header(self, interceptor, mock_response):
        req_data = {"url": "http://a.com", "authentication": "unauthenticated"}
        result = await interceptor.handle_response(req_data, mock_response(401, {}))
        assert result["authentication"] == "unauthenticated"

    async def test_401_overwrites_rejected_credential(self, interceptor, mock_response):
        # A 401 means the sent credential was rejected, so the server's challenge
        # -- not the failed "bearer" -- is the authoritative label. The raw
        # challenge is still recorded for evidence.
        req_data = {"url": "http://a.com", "authentication": "bearer"}
        result = await interceptor.handle_response(
            req_data, mock_response(401, {"www-authenticate": "Basic"})
        )
        assert result["authentication"] == "basic"
        assert result["auth_challenge"] == "Basic"

    async def test_401_bearer_rejected_by_negotiate(self, interceptor, mock_response):
        # The motivating scenario: a bearer token met with a Negotiate challenge.
        # The rejected bearer must not stick as the request's auth.
        req_data = {"url": "http://a.com", "authentication": "bearer"}
        result = await interceptor.handle_response(
            req_data, mock_response(401, {"www-authenticate": "Negotiate"})
        )
        assert result["authentication"] == "negotiate"

    async def test_302_idp(self, interceptor, mock_response):
        # The label carries only the scheme; the IdP host stays in 'idp_redirect'.
        req_data = {"url": "http://a.com", "authentication": "unauthenticated"}
        result = await interceptor.handle_response(
            req_data, mock_response(302, {"location": "https://x.auth0.com/authorize"})
        )
        assert result["authentication"] == "oauth"
        assert result["idp_redirect"] == "x.auth0.com"

    async def test_307_idp(self, interceptor, mock_response):
        req_data = {"url": "http://a.com", "authentication": "unauthenticated"}
        result = await interceptor.handle_response(
            req_data, mock_response(307, {"location": "https://login.microsoftonline.com/t/oauth2"})
        )
        assert result["authentication"] == "oauth"
        assert result["idp_redirect"] == "login.microsoftonline.com"

    async def test_302_relative_oauth_location(self, interceptor, mock_response):
        # A same-origin relative redirect to an authorization endpoint still
        # classifies -- the path keeps the detection truthy despite the empty host.
        req_data = {"url": "http://a.com", "authentication": "unauthenticated"}
        result = await interceptor.handle_response(
            req_data, mock_response(302, {"location": "/oauth/authorize"})
        )
        assert result["authentication"] == "oauth"
        assert result["idp_redirect"] == "/oauth/authorize"

    async def test_301_non_idp(self, interceptor, mock_response):
        req_data = {"url": "http://a.com", "authentication": "unauthenticated"}
        result = await interceptor.handle_response(
            req_data, mock_response(301, {"location": "https://example.com/new"})
        )
        assert result["authentication"] == "unauthenticated"

    async def test_none_response(self, interceptor):
        req_data = {"url": "http://a.com", "authentication": "unauthenticated"}
        result = await interceptor.handle_response(req_data, None)
        assert result["status"] == 0
        assert "response_error" in result

    async def test_none_response_not_duplicated(self, interceptor):
        req_data = {"url": "http://a.com", "authentication": "unauthenticated"}
        await interceptor.handle_response(req_data, None)
        await interceptor.handle_response(req_data, None)
        assert interceptor.requests.count(req_data) == 1

    async def test_appended_to_list(self, interceptor, mock_response):
        for i in range(3):
            req_data = {"url": f"http://a.com/{i}", "authentication": "unauthenticated"}
            await interceptor.handle_response(req_data, mock_response(200))
        assert len(interceptor.requests) == 3


class TestGetHeaderValue:
    def test_case_insensitive(self, interceptor):
        headers = {"Content-Type": "application/json", "X-Custom": "v"}
        assert interceptor._get_header_value(headers, "content-type") == "application/json"
        assert interceptor._get_header_value(headers, "x-custom") == "v"
        assert interceptor._get_header_value(headers, "missing") is None

    def test_empty(self, interceptor):
        assert interceptor._get_header_value({}, "x") is None


class TestInterceptorState:
    def test_get_requests_returns_copy(self, interceptor):
        interceptor.requests.append({"url": "http://a"})
        copy = interceptor.get_requests()
        copy.append({"url": "http://b"})
        assert len(interceptor.requests) == 1

    def test_clear(self, interceptor):
        interceptor.requests.extend([{"url": "a"}, {"url": "b"}])
        interceptor.clear()
        assert interceptor.requests == []

    def test_initial_state(self, interceptor):
        assert interceptor.requests == []
        assert interceptor.source_url == ""
