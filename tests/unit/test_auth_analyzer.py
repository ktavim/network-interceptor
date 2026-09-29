"""Tests for crawler.network.auth_analyzer."""
import base64

import pytest
from crawler.network.auth_analyzer import (
    detect_authentication,
    sent_auth_scheme,
    detect_auth_challenge,
    is_idp_redirect,
    aggregate_by_origin,
    _parse_challenges,
    strip_url,
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


class TestSentAuthScheme:
    @pytest.mark.parametrize("value, scheme", [
        ("Bearer abc.def.ghi", "Bearer"),
        ("Basic dXNlcjpzZWNyZXQ=", "Basic"),
        ("Negotiate TlRMTVNTUAAB", "Negotiate"),
        ("NTLM TlRMTVNTUAAB", "NTLM"),
        ('Digest username="u", realm="r", response="abc"', "Digest"),
        ("AWS4-HMAC-SHA256 Credential=AKIA/s3/aws4_request, Signature=abc", "AWS4-HMAC-SHA256"),
    ])
    def test_keeps_only_the_scheme_word(self, value, scheme):
        assert sent_auth_scheme({"authorization": value}) == scheme

    def test_case_preserved_as_sent(self):
        # Evidence, not classification: detect_authentication decides the label.
        assert sent_auth_scheme({"authorization": "bearer abc"}) == "bearer"

    def test_case_insensitive_header_key(self):
        assert sent_auth_scheme({"Authorization": "Bearer abc"}) == "Bearer"

    def test_no_header(self):
        assert sent_auth_scheme({}) is None
        assert sent_auth_scheme({"x-api-key": "k"}) is None

    def test_empty_value(self):
        assert sent_auth_scheme({"authorization": ""}) is None

    def test_bare_credential_without_scheme_is_dropped(self):
        # Some clients send the raw token as the whole header. With nothing
        # after a space, the "first word" would be the secret itself.
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123"
        assert sent_auth_scheme({"authorization": jwt}) is None
        assert sent_auth_scheme({"authorization": "0123456789abcdef0123456789abcdef"}) is None

    def test_scheme_without_credentials_is_dropped(self):
        # Indistinguishable from a bare credential, so it is treated as one.
        assert sent_auth_scheme({"authorization": "Bearer"}) is None

    def test_empty_credentials_keep_the_scheme(self):
        # "Bearer " is what detect_authentication classifies as bearer, too.
        assert sent_auth_scheme({"authorization": "Bearer "}) == "Bearer"

    def test_overlong_first_word_is_dropped(self):
        # A secret followed by a space would otherwise pass as a "scheme".
        assert sent_auth_scheme({"authorization": "a" * 33 + " x"}) is None
        assert sent_auth_scheme({"authorization": "a" * 32 + " x"}) == "a" * 32

    def test_non_token_first_word_is_dropped(self):
        # '/' and '=' are not tchars: a base64 blob before a space is no scheme.
        assert sent_auth_scheme({"authorization": "dXNl/cg== x"}) is None
        assert sent_auth_scheme({"authorization": " Bearer x"}) is None

    @pytest.mark.parametrize("value", [
        "Bearer secret-token",
        "Basic c2VjcmV0",
        'Digest username="secret"',
        "secret-token",
    ])
    def test_credentials_never_survive(self, value):
        assert "secret" not in (sent_auth_scheme({"authorization": value}) or "")


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
        assert detect_auth_challenge("Kerberos") == detect_authentication(
            {"authorization": "Kerberos abc"}, "http://x"
        )
        assert detect_auth_challenge("Negotiate TlRMTVNTUAAC") == detect_authentication(
            {"authorization": "Negotiate TlRMTVNTUAAC"}, "http://x"
        )

    def test_scheme_is_a_whole_token(self):
        # A prefix match would take "Basically" for Basic.
        assert detect_auth_challenge("Basically realm=x") == "other"
        assert detect_auth_challenge("Bearers") == "other"

    @pytest.mark.parametrize("challenge,expected", [
        # IIS Windows Authentication's default: Negotiate and NTLM as two
        # headers, which Playwright joins into one comma-separated value. The
        # server takes either, so the endpoint is publishable through
        # Negotiate and the NTLM offer does not make it a blocker.
        ("Negotiate, NTLM", "negotiate"),
        # An endpoint that takes Bearer as well as Basic is publishable with
        # Bearer, whichever side of the comma each is on.
        ('Bearer realm="api", Basic realm="api"', "bearer"),
        ('Basic realm="api", Bearer realm="api"', "bearer"),
        # Empty list elements and odd whitespace are legal.
        ("Negotiate,, NTLM", "negotiate"),
        ("Negotiate ,NTLM", "negotiate"),
        ("  Negotiate\t,\tNTLM  ", "negotiate"),
    ])
    def test_multiple_challenges_pick_most_favorable(self, challenge, expected):
        assert detect_auth_challenge(challenge) == expected

    def test_ties_keep_server_order(self):
        assert detect_auth_challenge("Basic, NTLM") == "basic"
        assert detect_auth_challenge("NTLM, Basic") == "ntlm"

    def test_selection_reads_auth_rank_downward(self):
        # Within one response any offered scheme suffices, so the lowest rank
        # wins -- the opposite direction from aggregate_by_origin, where every
        # URL must work and the highest rank wins. The table is shared, so an
        # unnamed scheme loses to bearer and to negotiate here -- the known
        # path is preferred over one the tool cannot vouch for, and offering
        # Digest alongside is no blocker -- and wins only against Basic or
        # NTLM, where every offer blocks.
        assert detect_auth_challenge('Bearer realm="a", Digest realm="a"') == "bearer"
        assert detect_auth_challenge('Digest realm="a", Negotiate') == "negotiate"
        assert detect_auth_challenge('Basic realm="a", Digest realm="a"') == "other"

    def test_rfc7235_example_parses_both_challenges(self):
        # RFC 7235's own multi-challenge example, quoted-pair included.
        challenge = 'Newauth realm="apps", type=1, title="Login to \\"apps\\"", Basic realm="simple"'
        assert _parse_challenges(challenge) == [("Newauth", None), ("Basic", None)]
        assert detect_auth_challenge(challenge) == "other"

    # Under the lowest-rank rule a spurious extra challenge -- tagged "other"
    # -- would beat basic or ntlm but lose to bearer, so these cases lead with
    # a blocker: a mis-split shows up as a changed label.
    @pytest.mark.parametrize("challenge,expected", [
        # A comma inside a quoted parameter does not split the list.
        ('Basic realm="a, b"', "basic"),
        ('NTLM realm="a, Bearer"', "ntlm"),
        # An escaped quote does not close the quoted string.
        ('NTLM realm="a\\"b, Bearer"', "ntlm"),
        # A comma followed by name=value continues the same challenge.
        ("Basic realm=x, charset=UTF-8", "basic"),
        ('Basic realm="x", charset="UTF-8", title="a, b"', "basic"),
        ('Basic realm = "x" , charset = "UTF-8"', "basic"),
    ])
    def test_parameters_are_not_challenges(self, challenge, expected):
        assert detect_auth_challenge(challenge) == expected

    def test_token68_is_not_a_parameter(self):
        # token68 padding is not the "=" of an auth-param, and the list still
        # splits after it.
        assert _parse_challenges("Negotiate YIIC==, NTLM") == [("Negotiate", "YIIC=="), ("NTLM", None)]
        assert _parse_challenges("Negotiate YIIC=, Basic realm=x") == [("Negotiate", "YIIC="), ("Basic", None)]
        assert _parse_challenges("NTLM TlRMTVNTUAAC") == [("NTLM", "TlRMTVNTUAAC")]
        # A param is not a token68: "=" and a value follow the word.
        assert _parse_challenges("Basic realm=x") == [("Basic", None)]
        # The token68 reaches the mechanism sniff: with NTLM in flight the
        # Negotiate challenge ties with Basic and server order decides.
        assert detect_auth_challenge("Negotiate TlRMTVNTUAAC, Basic realm=x") == "ntlm"
        assert detect_auth_challenge("Negotiate YIIC==, NTLM") == "negotiate"

    def test_negotiate_token_resolves_the_mechanism_in_flight(self):
        # A 401 "Negotiate <token>" is the server's handshake continuation, and
        # the token names the mechanism being exchanged. It resolves as the
        # request side's credential does, so the 401 override in the
        # interceptor cannot downgrade an NTLM exchange to "negotiate".
        raw_ntlm = b"\x60\x28\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x1e" + _NTLM_MAGIC + b"\x02\x00\x00\x00"
        assert detect_auth_challenge(_negotiate(raw_ntlm)["authorization"]) == "ntlm"
        raw_krb = b"\x60\x1e\x06\x09" + _KRB5_OID + b"\xa0\x11\x30\x0f"
        assert detect_auth_challenge(_negotiate(raw_krb)["authorization"]) == "kerberos"
        # A token that names no mechanism stays "negotiate".
        assert detect_auth_challenge("Negotiate " + base64.b64encode(b"\x60\x04zzzz").decode()) == "negotiate"

    @pytest.mark.parametrize("challenge", [
        ",",
        " , ,",
        '"quoted"',
        "=",
        "==, ==",
        'Basic"realm"',
        'Bearer realm="unterminated',
        "Negotiate abc def",
        "Basic realm=",
        "Basic realm=x,",
        ", Basic",
        "\x00\xff",
    ])
    def test_malformed_input_never_raises(self, challenge):
        assert detect_auth_challenge(challenge) in {
            "basic", "bearer", "ntlm", "kerberos", "negotiate", "other",
        }

    def test_malformed_element_does_not_hide_its_neighbours(self):
        assert detect_auth_challenge('"garbage", Basic realm=x') == "basic"
        assert detect_auth_challenge('NTLM, =, Bearer realm="x"') == "bearer"
        assert _parse_challenges('NTLM, =, Bearer realm="x"') == [("NTLM", None), ("Bearer", None)]


class TestIsIdpRedirect:
    @pytest.mark.parametrize("url", [
        "https://myapp.auth0.com/authorize",
        "https://dev-123.okta.com/oauth2/default",
        "https://dev-123.oktapreview.com/app",
        "https://login.microsoftonline.com/t/oauth2",
        "https://accounts.google.com/o/oauth2/auth",
        "https://cognito-idp.us-east-1.amazonaws.com/p",
        "https://mypool.amazoncognito.com/login",
        "https://app.onelogin.com/trust/saml2",
        "https://sso.pingidentity.com/sso",
    ])
    def test_known_idp_host(self, url):
        assert is_idp_redirect(url) is True

    # An OAuth/OIDC-shaped path on an unknown host counts too: it looks like an
    # authorization endpoint, often the app's own.
    @pytest.mark.parametrize("url", [
        "https://mysite.com/oauth/authorize",
        "https://mysite.com/oidc/auth",
    ])
    def test_generic_oauth_path(self, url):
        assert is_idp_redirect(url) is True

    def test_relative_location(self):
        # A relative Location has no host; the path alone decides.
        assert is_idp_redirect("/oauth/authorize") is True

    def test_query_string_ignored_for_known_path(self):
        assert is_idp_redirect(
            "https://mysite.com/oauth/authorize?state=abc&redirect_uri=/cb"
        ) is True

    def test_no_match(self):
        assert is_idp_redirect("https://www.example.com/dashboard") is False

    def test_empty_string(self):
        assert is_idp_redirect("") is False

    def test_oauth_in_query_not_path(self):
        assert is_idp_redirect("https://example.com/login?r=/oauth/cb") is False

    def test_case_insensitive_domain(self):
        assert is_idp_redirect("https://MyApp.Auth0.COM/authorize") is True


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
        counts = {e["host"]: len(e["urls"]) for e in result}
        assert counts == {"a.com": 2, "b.com": 1}

    def test_scheme_separates_services(self):
        # http://a.com and https://a.com are different listeners to publish, so
        # each keeps its own label and evidence: the Basic demanded over http
        # must not become the https service's label.
        reqs = [
            {"url": "http://a.com/login", "authentication": "basic", "status": 401},
            {"url": "https://a.com/api", "authentication": "bearer", "status": 200},
        ]
        result = {e["scheme"]: e for e in aggregate_by_origin(reqs)}
        assert set(result) == {"http", "https"}
        assert result["http"]["authentication"] == "basic"
        assert result["http"]["urls"][result["http"]["evidence_index"]]["status"] == 401
        assert result["https"]["authentication"] == "bearer"
        assert result["https"]["urls"][result["https"]["evidence_index"]]["status"] == 200

    def test_port_separates_services(self):
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
        assert len(result[0]["urls"]) == 2
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

    def test_other_outranks_negotiate(self):
        # A scheme the tool cannot name is unsupported for the publish
        # (blocker-tier) where a Negotiate handshake is merely unresolved
        # (review-tier), so the unnamed URL becomes the label and the evidence
        # row instead of being swallowed by the common Negotiate case. A named
        # blocker on the origin still wins as the more informative label.
        reqs = [
            {"url": "http://a.com/1", "authentication": "negotiate"},
            {"url": "http://a.com/2", "authentication": "other"},
            {"url": "http://a.com/3", "authentication": "negotiate"},
        ]
        result = aggregate_by_origin(reqs)
        assert result[0]["authentication"] == "other"
        assert result[0]["evidence_index"] == 1

        reqs.append({"url": "http://a.com/4", "authentication": "basic"})
        result = aggregate_by_origin(reqs)
        assert result[0]["authentication"] == "basic"
        assert result[0]["evidence_index"] == 3

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

    def test_any_answer_outranks_no_response(self):
        # A 200 without credentials shows the origin takes bare requests; an
        # aborted request next to it must not send the origin to review.
        reqs = [
            {"url": "http://a.com/config", "authentication": "no_response", "status": 0},
            {"url": "http://a.com/data", "authentication": "unauthenticated", "status": 200},
        ]
        result = aggregate_by_origin(reqs)
        assert result[0]["authentication"] == "unauthenticated"
        assert result[0]["evidence_index"] == 1

    def test_no_response_labels_an_origin_nothing_answered(self):
        reqs = [
            {"url": "http://a.com/1", "authentication": "no_response", "status": 0},
            {"url": "http://a.com/2", "authentication": "no_response", "status": 0},
        ]
        result = aggregate_by_origin(reqs)
        assert result[0]["authentication"] == "no_response"
        assert result[0]["evidence_index"] == 0

    def test_sent_scheme_on_a_failed_request_outranks_no_response(self):
        reqs = [
            {"url": "http://a.com/1", "authentication": "no_response", "status": 0},
            {"url": "http://a.com/2", "authentication": "bearer", "status": 0},
        ]
        result = aggregate_by_origin(reqs)
        assert result[0]["authentication"] == "bearer"

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


class TestStripUrl:
    def test_drops_query(self):
        stripped = strip_url("https://a.com/search?q=secret&api_key=abc123")
        assert stripped == "https://a.com/search"
        assert "secret" not in stripped
        assert "abc123" not in stripped

    def test_drops_fragment(self):
        assert strip_url("https://a.com/app#/route?x=1") == "https://a.com/app"

    def test_drops_userinfo(self):
        assert strip_url("http://user:p%40ss@a.com/x") == "http://a.com/x"

    def test_url_without_query_is_unchanged(self):
        assert strip_url("https://a.com/path/to/thing") == "https://a.com/path/to/thing"

    def test_keeps_explicit_port_and_ipv6_brackets(self):
        assert strip_url("https://a.com:8443/x?y=1") == "https://a.com:8443/x"
        assert strip_url("http://[::1]:8080/x?y=1") == "http://[::1]:8080/x"


class TestAggregateByOriginUrls:
    def test_urls_preserve_capture_order(self):
        reqs = [
            {"url": "http://a.com/1", "authentication": "unauthenticated"},
            {"url": "http://b.com/1", "authentication": "unauthenticated"},
            {"url": "http://a.com/2", "authentication": "unauthenticated"},
        ]
        by_host = {e["host"]: e for e in aggregate_by_origin(reqs)}
        assert [u["url"] for u in by_host["a.com"]["urls"]] == ["http://a.com/1", "http://a.com/2"]
        assert [u["url"] for u in by_host["b.com"]["urls"]] == ["http://b.com/1"]

    def test_urls_are_copies_of_the_records(self):
        # Redaction happens at capture; nothing is reshaped or dropped here.
        req = {"url": "http://a.com/1", "authentication": "basic", "status": 401, "page_url": "http://p"}
        entry = aggregate_by_origin([req])[0]
        assert entry["urls"][0] == req
        assert entry["urls"][0] is not req

    def test_requests_without_origin_are_not_listed(self):
        reqs = [
            {"url": "http://a.com/1", "authentication": "unauthenticated"},
            {"url": "data:text/plain,hi", "authentication": "unauthenticated"},
            {"url": "http://a.com/2", "authentication": "unauthenticated"},
        ]
        result = aggregate_by_origin(reqs)
        assert len(result) == 1
        assert [u["url"] for u in result[0]["urls"]] == ["http://a.com/1", "http://a.com/2"]

    def test_evidence_index_is_the_first_url_at_the_winning_rank(self):
        # A later request at the same rank does not displace the first one seen.
        reqs = [
            {"url": "http://a.com/1", "authentication": "unauthenticated", "status": 200},
            {"url": "http://a.com/2", "authentication": "basic", "status": 401},
            {"url": "http://a.com/3", "authentication": "basic", "status": 403},
        ]
        entry = aggregate_by_origin(reqs)[0]
        assert entry["evidence_index"] == 1
        assert entry["urls"][1]["url"] == "http://a.com/2"
        assert entry["urls"][1]["status"] == 401

    def test_evidence_index_starts_at_the_first_request(self):
        reqs = [
            {"url": "http://a.com/1", "authentication": "bearer"},
            {"url": "http://a.com/2", "authentication": "unauthenticated"},
        ]
        assert aggregate_by_origin(reqs)[0]["evidence_index"] == 0

    def test_evidence_index_is_per_origin(self):
        reqs = [
            {"url": "http://a.com/1", "authentication": "unauthenticated"},
            {"url": "http://b.com/1", "authentication": "unauthenticated"},
            {"url": "http://b.com/2", "authentication": "ntlm"},
            {"url": "http://a.com/2", "authentication": "unauthenticated"},
            {"url": "http://a.com/3", "authentication": "basic"},
        ]
        by_host = {e["host"]: e for e in aggregate_by_origin(reqs)}
        assert by_host["a.com"]["evidence_index"] == 2
        assert by_host["b.com"]["evidence_index"] == 1

    def test_evidence_index_counts_only_listed_urls(self):
        # A request with no origin is skipped and takes no position in `urls`,
        # so the index is not the request's position in the input.
        reqs = [
            {"url": "http://a.com/1", "authentication": "unauthenticated"},
            {"url": "data:text/plain,hi", "authentication": "unauthenticated"},
            {"url": "http://a.com/2", "authentication": "basic"},
        ]
        entry = aggregate_by_origin(reqs)[0]
        assert entry["evidence_index"] == 1
        assert entry["urls"][1]["url"] == "http://a.com/2"
