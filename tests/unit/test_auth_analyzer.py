"""Tests for crawler.network.auth_analyzer."""
import base64

import pytest
from crawler.network.auth_analyzer import (
    detect_authentication,
    detect_auth_challenge,
    detect_idp_redirect,
    aggregate_by_origin,
)


# Mechanism signatures used to craft realistic SPNEGO tokens for the tests.
_NTLM_MAGIC = b"NTLMSSP\x00"
_KRB5_OID = bytes((0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02))
_MS_KRB5_OID = bytes((0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02))


def _negotiate(raw: bytes) -> dict:
    """Build an Authorization header carrying a base64 'Negotiate' token."""
    return {"authorization": "Negotiate " + base64.b64encode(raw).decode("ascii")}


class TestDetectAuthentication:
    def test_bearer(self):
        assert detect_authentication({"authorization": "Bearer abc"}, "http://x") == "bearer"

    def test_bearer_empty_token(self):
        assert detect_authentication({"authorization": "Bearer "}, "http://x") == "bearer"

    def test_basic(self):
        assert detect_authentication({"authorization": "Basic dXNlcg=="}, "http://x") == "basic"

    def test_negotiate_ntlm_prefix_fast_path(self):
        # base64 of "NTLMSSP\0\x01..." starts with "TlR" -- the cheap fast path.
        assert detect_authentication({"authorization": "Negotiate TlRMTVNTUAAB"}, "http://x") == "ntlm"

    def test_negotiate_ntlm_inside_spnego(self):
        # NTLM mechToken wrapped in a SPNEGO blob (token starts 0x60, not "TlR")
        # must still be caught by the byte-signature scan.
        raw = b"\x60\x28\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x1e" + _NTLM_MAGIC + b"\x01\x00\x00\x00"
        assert detect_authentication(_negotiate(raw), "http://x") == "ntlm"

    def test_negotiate_kerberos_oid(self):
        raw = b"\x60\x1e\x06\x09" + _KRB5_OID + b"\xa0\x11\x30\x0f"
        assert detect_authentication(_negotiate(raw), "http://x") == "kerberos"

    def test_negotiate_ms_kerberos_oid(self):
        raw = b"\x60\x1e\x06\x09" + _MS_KRB5_OID + b"\xa0\x11\x30\x0f"
        assert detect_authentication(_negotiate(raw), "http://x") == "kerberos"

    def test_negotiate_ntlm_wins_over_offered_kerberos(self):
        # SPNEGO that lists the Kerberos OID but actually carries an NTLM
        # mechToken -> NTLM is in use, and NTLM is the severity-relevant call.
        raw = b"\x60\x30\x06\x09" + _KRB5_OID + b"\xa2\x12" + _NTLM_MAGIC + b"\x03\x00\x00\x00"
        assert detect_authentication(_negotiate(raw), "http://x") == "ntlm"

    def test_negotiate_unresolved_token(self):
        # Valid base64 but no recognizable mechanism signature -> negotiate bucket.
        raw = b"\x60\x06\x06\x04\x01\x02\x03\x04"
        assert detect_authentication(_negotiate(raw), "http://x") == "negotiate"

    def test_negotiate_invalid_base64(self):
        # Scheme is certainly SPNEGO even if the token is junk.
        assert detect_authentication({"authorization": "Negotiate xyz123"}, "http://x") == "negotiate"

    def test_ntlm_direct(self):
        assert detect_authentication({"authorization": "NTLM abc"}, "http://x") == "ntlm"

    def test_kerberos_direct(self):
        assert detect_authentication({"authorization": "Kerberos abc"}, "http://x") == "kerberos"

    def test_unnamed_scheme_is_other(self):
        # A present-but-unrecognized scheme (Digest) is a real, unnamed mechanism,
        # classified as "other" -- not "unknown" -- mirroring the interceptor's
        # "other" challenge handling.
        assert detect_authentication({"authorization": "Digest abc"}, "http://x") == "other"

    def test_case_insensitive_header_key(self):
        assert detect_authentication({"Authorization": "Bearer abc"}, "http://x") == "bearer"

    @pytest.mark.parametrize("header", [
        "x-api-key", "x-auth-token", "x-auth", "api-key", "apikey", "auth-token"
    ])
    def test_api_key_headers(self, header):
        result = detect_authentication({header: "k"}, "http://x")
        assert result == "api_key"

    @pytest.mark.parametrize("param", ["api_key", "apikey", "key", "auth_token", "token"])
    def test_api_key_query_params(self, param):
        url = f"http://api.example.com/v1?{param}=abc"
        assert detect_authentication({}, url) == "api_key"

    def test_cookie_lowercase_ignored(self):
        assert detect_authentication({"cookie": "sid=abc"}, "http://x") == "unauthenticated"

    def test_cookie_capital_ignored(self):
        assert detect_authentication({"Cookie": "sid=abc"}, "http://x") == "unauthenticated"

    def test_no_auth(self):
        assert detect_authentication({}, "http://x") == "unauthenticated"

    def test_auth_header_priority_over_api_key(self):
        assert detect_authentication(
            {"authorization": "Bearer abc", "x-api-key": "k"}, "http://x"
        ) == "bearer"

    def test_api_key_priority_over_cookie(self):
        assert detect_authentication(
            {"x-api-key": "k", "cookie": "sid=abc"}, "http://x"
        ) == "api_key"

    def test_api_key_header_priority_over_query_param(self):
        assert detect_authentication(
            {"x-api-key": "k"}, "http://x?api_key=abc"
        ) == "api_key"

    def test_non_matching_query_params(self):
        assert detect_authentication({}, "http://x?user=a&page=1") == "unauthenticated"


class TestDetectAuthChallenge:
    @pytest.mark.parametrize("challenge,expected", [
        ("Basic", "basic"),
        ('Basic realm="corp"', "basic"),
        ("Bearer", "bearer"),
        ('Bearer realm="api", error="invalid_token"', "bearer"),
        ("NTLM", "ntlm"),
        ("NTLM TlRMTVNTUAAC", "ntlm"),
        ("Negotiate", "negotiate"),
        ("Negotiate YIIC", "negotiate"),
    ])
    def test_named_schemes(self, challenge, expected):
        assert detect_auth_challenge(challenge) == expected

    @pytest.mark.parametrize("challenge,expected", [
        ("basic", "basic"),
        ("BASIC", "basic"),
        ("NeGoTiAtE", "negotiate"),
        ("ntlm", "ntlm"),
    ])
    def test_case_insensitive(self, challenge, expected):
        assert detect_auth_challenge(challenge) == expected

    def test_unnamed_scheme_is_other(self):
        # A real but unnamed mechanism -- not an absence of signal.
        assert detect_auth_challenge('Digest realm="t", qop="auth"') == "other"

    def test_empty_is_other(self):
        # The interceptor gates on a present header, so this is defensive only:
        # the function stays total rather than returning None for an empty input.
        assert detect_auth_challenge("") == "other"

    def test_shares_vocabulary_with_detect_authentication(self):
        # The two must not drift: a scheme demanded and a scheme observed have to
        # normalize to the same tag, or _auth_rank will rank them differently.
        assert detect_auth_challenge("Basic") == detect_authentication(
            {"authorization": "Basic dXNlcg=="}, "http://x"
        )
        assert detect_auth_challenge("NTLM") == detect_authentication(
            {"authorization": "NTLM abc"}, "http://x"
        )


class TestDetectIdpRedirect:
    # A known IdP host resolves to the host -- tenant included.
    @pytest.mark.parametrize("url,expected", [
        ("https://myapp.auth0.com/authorize", "myapp.auth0.com"),
        ("https://dev-123.okta.com/oauth2/default", "dev-123.okta.com"),
        ("https://dev-123.oktapreview.com/app", "dev-123.oktapreview.com"),
        ("https://login.microsoftonline.com/t/oauth2", "login.microsoftonline.com"),
        ("https://accounts.google.com/o/oauth2/auth", "accounts.google.com"),
        ("https://cognito-idp.us-east-1.amazonaws.com/p", "cognito-idp.us-east-1.amazonaws.com"),
        ("https://mypool.amazoncognito.com/login", "mypool.amazoncognito.com"),
        ("https://app.onelogin.com/trust/saml2", "app.onelogin.com"),
        ("https://sso.pingidentity.com/sso", "sso.pingidentity.com"),
    ])
    def test_known_idp_host(self, url, expected):
        assert detect_idp_redirect(url) == expected

    # An OAuth/OIDC-shaped path on an unknown host keeps the path, so the weaker
    # claim ("looks like an authorization endpoint") stays distinguishable from a
    # known IdP host.
    @pytest.mark.parametrize("url,expected", [
        ("https://mysite.com/oauth/authorize", "mysite.com/oauth/authorize"),
        ("https://mysite.com/oidc/auth", "mysite.com/oidc/auth"),
    ])
    def test_generic_oauth_path(self, url, expected):
        assert detect_idp_redirect(url) == expected

    def test_relative_location_stays_truthy(self):
        # A relative Location has no netloc; the path alone must still be a
        # non-empty (truthy) result or the caller would drop the detection.
        assert detect_idp_redirect("/oauth/authorize") == "/oauth/authorize"

    def test_query_string_dropped(self):
        # state/nonce/redirect_uri must not survive into the stored evidence.
        assert detect_idp_redirect(
            "https://mysite.com/oauth/authorize?state=abc&redirect_uri=/cb"
        ) == "mysite.com/oauth/authorize"

    def test_no_match(self):
        assert detect_idp_redirect("https://www.example.com/dashboard") is None

    def test_empty_string(self):
        assert detect_idp_redirect("") is None

    def test_oauth_in_query_not_path(self):
        assert detect_idp_redirect("https://example.com/login?r=/oauth/cb") is None

    def test_case_insensitive_domain(self):
        assert detect_idp_redirect("https://MyApp.Auth0.COM/authorize") == "myapp.auth0.com"


def _origins(result) -> set:
    return {(e["scheme"], e["host"], e["port"]) for e in result}


class TestAggregateByOrigin:
    def test_single_origin(self):
        reqs = [{"url": "http://a.com/x", "authentication": "bearer"}]
        result = aggregate_by_origin(reqs)
        assert len(result) == 1
        assert result[0]["scheme"] == "http"
        assert result[0]["host"] == "a.com"
        assert result[0]["port"] == 80
        assert result[0]["authentication"] == "bearer"

    def test_groups_by_origin(self):
        reqs = [
            {"url": "http://a.com/1", "authentication": "unauthenticated"},
            {"url": "http://a.com/2", "authentication": "unauthenticated"},
            {"url": "http://b.com/1", "authentication": "bearer"},
        ]
        result = aggregate_by_origin(reqs)
        assert _origins(result) == {("http", "a.com", 80), ("http", "b.com", 80)}
        counts = {e["host"]: e["request_count"] for e in result}
        assert counts == {"a.com": 2, "b.com": 1}

    def test_scheme_separates_findings(self):
        # http://a.com and https://a.com are different listeners to publish, so
        # each keeps its own label and evidence: the Basic demanded over http
        # must not become the https service's label.
        reqs = [
            {
                "url": "http://a.com/login",
                "authentication": "basic",
                "status": 401,
                "request_headers": {"X-Seen-On": "http"},
            },
            {
                "url": "https://a.com/api",
                "authentication": "bearer",
                "status": 200,
                "request_headers": {"X-Seen-On": "https"},
            },
        ]
        result = {e["scheme"]: e for e in aggregate_by_origin(reqs)}
        assert set(result) == {"http", "https"}
        assert result["http"]["authentication"] == "basic"
        assert result["http"]["status_code"] == 401
        assert result["https"]["authentication"] == "bearer"
        assert result["https"]["status_code"] == 200
        assert "X-Seen-On: https" in result["https"]["headers_snippet"]

    def test_port_separates_findings(self):
        reqs = [
            {"url": "https://a.com/1", "authentication": "bearer"},
            {"url": "https://a.com:8443/1", "authentication": "ntlm"},
        ]
        result = aggregate_by_origin(reqs)
        assert _origins(result) == {("https", "a.com", 443), ("https", "a.com", 8443)}

    def test_explicit_default_port_is_same_origin(self):
        reqs = [
            {"url": "https://a.com/1", "authentication": "unauthenticated"},
            {"url": "https://a.com:443/2", "authentication": "bearer"},
        ]
        result = aggregate_by_origin(reqs)
        assert len(result) == 1
        assert result[0]["port"] == 443
        assert result[0]["request_count"] == 2
        assert result[0]["authentication"] == "bearer"

    def test_host_is_bare_hostname(self):
        # `host` is a cross-service contract (inventory -> vip-wizard): no port,
        # no credentials, lowercased.
        reqs = [{"url": "https://user:secret@A.com:8443/x", "authentication": "basic"}]
        result = aggregate_by_origin(reqs)
        assert result[0]["host"] == "a.com"
        assert result[0]["port"] == 8443

    def test_upgrades_from_none_to_actual(self):
        reqs = [
            {"url": "http://a.com/1", "authentication": "unauthenticated"},
            {"url": "http://a.com/2", "authentication": "bearer"},
        ]
        result = aggregate_by_origin(reqs)
        assert result[0]["authentication"] == "bearer"

    def test_basic_challenge_outranks_accepted_bearer(self):
        # A Basic scheme (blocker-tier) -- here demanded by a 401, which labels the
        # request with the bare scheme -- is the host's most notable auth and must
        # not be masked by an accepted bearer token on another endpoint.
        reqs = [
            {"url": "http://a.com/1", "authentication": "basic"},
            {"url": "http://a.com/2", "authentication": "bearer"},
        ]
        result = aggregate_by_origin(reqs)
        assert result[0]["authentication"] == "basic"

    def test_keeps_better_auth(self):
        reqs = [
            {"url": "http://a.com/1", "authentication": "bearer"},
            {"url": "http://a.com/2", "authentication": "unauthenticated"},
        ]
        result = aggregate_by_origin(reqs)
        assert result[0]["authentication"] == "bearer"

    def test_basic_outranks_negotiate_challenge(self):
        # Ranking is purely by scheme: Basic (blocker-tier) outranks a Negotiate
        # challenge (review-tier) regardless of which was actually accepted.
        reqs = [
            {"url": "http://a.com/admin", "authentication": "negotiate"},
            {"url": "http://a.com/login", "authentication": "basic"},
        ]
        result = aggregate_by_origin(reqs)
        assert result[0]["authentication"] == "basic"

    def test_challenge_stands_without_accepted_credential(self):
        # A host seen only via a rejected-and-challenged request keeps the
        # challenge as its label -- the rejected credential does not resurface.
        reqs = [
            {"url": "http://a.com/admin", "authentication": "negotiate"},
        ]
        result = aggregate_by_origin(reqs)
        assert result[0]["authentication"] == "negotiate"

    def test_challenge_not_overwritten_by_later_unauthenticated(self):
        # A real 401 challenge outranks "no auth", so a later unauthenticated
        # request on the same host must not overwrite it (regression guard for
        # the removed NO_AUTH-only upgrade path).
        reqs = [
            {"url": "http://a.com/admin", "authentication": "negotiate"},
            {"url": "http://a.com/health", "authentication": "unauthenticated"},
        ]
        result = aggregate_by_origin(reqs)
        assert result[0]["authentication"] == "negotiate"

    def test_ntlm_outranks_negotiate(self):
        # NTLM (blocker-tier) is the host's most notable auth over a plain
        # Negotiate/SPNEGO handshake (review-tier).
        reqs = [
            {"url": "http://a.com/1", "authentication": "negotiate"},
            {"url": "http://a.com/2", "authentication": "ntlm"},
        ]
        result = aggregate_by_origin(reqs)
        assert result[0]["authentication"] == "ntlm"

    def test_other_challenge_outranks_unknown(self):
        # An "other" 401 (a named but unrecognized challenge scheme) outranks
        # an unclassifiable header, so it wins the host label. Deterministic tiebreak:
        # the unknown is seen first here, yet "other" still represents the host.
        reqs = [
            {"url": "http://a.com/1", "authentication": "unknown"},
            {"url": "http://a.com/2", "authentication": "other"},
        ]
        result = aggregate_by_origin(reqs)
        assert result[0]["authentication"] == "other"

    def test_oauth_redirect_outranks_unauthenticated(self):
        # The "oauth" IdP-redirect label outranks unauthenticated.
        reqs = [
            {"url": "http://a.com/1", "authentication": "unauthenticated"},
            {"url": "http://a.com/2", "authentication": "oauth"},
        ]
        result = aggregate_by_origin(reqs)
        assert result[0]["authentication"] == "oauth"

    @pytest.mark.parametrize("url", ["not-a-url", "data:text/plain,hi", "http://a.com:bad/x"])
    def test_skips_requests_without_origin(self, url):
        reqs = [{"url": url, "authentication": "unauthenticated"}]
        assert aggregate_by_origin(reqs) == []

    def test_missing_authentication_defaults_to_unauthenticated(self):
        reqs = [{"url": "http://a.com/x"}]
        result = aggregate_by_origin(reqs)
        assert result[0]["authentication"] == "unauthenticated"

    def test_empty_input(self):
        assert aggregate_by_origin([]) == []
