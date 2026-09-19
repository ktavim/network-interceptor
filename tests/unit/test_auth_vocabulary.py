"""Contract tests for the authentication tag vocabulary.

The crawler labels a request with a short authentication tag; api.translate maps
that tag to the FE's AuthMethod, and auth_analyzer._auth_rank ranks it for host
aggregation. Both are exact lookups, so a producer emitting a tag neither side
knows would degrade silently to unknown/review -- and a tag no producer emits
leaves dead entries behind, as the retired "/oidc" and "apikey" branches did.
These tests pin the vocabulary from both ends.
"""
import base64

import pytest

from api.models import AuthMethod
from api.translate import tag_to_auth_method
from crawler.network import NetworkInterceptor
from crawler.network.auth_analyzer import (
    _AUTH_RANK,
    aggregate_by_origin,
    detect_authentication,
)


# Every tag that can land in a request's 'authentication' field.
SCRAPER_AUTH_TAGS = {
    "ntlm",
    "kerberos",
    "negotiate",
    "oauth",
    "basic",
    "bearer",
    "api_key",
    "other",
    "unauthenticated",
}

_KRB5_OID = bytes((0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02))


def _negotiate_kerberos() -> str:
    """A SPNEGO token carrying the Kerberos mech OID."""
    raw = b"\x60\x1e\x06\x09" + _KRB5_OID + b"\xa0\x11\x30\x0f"
    return "Negotiate " + base64.b64encode(raw).decode("ascii")


def _observed_tags() -> set:
    """Drive every producer that writes 'authentication' and collect its tags."""
    tags = set()

    # handle_request -> detect_authentication, from the request's own headers.
    for headers in (
        {"authorization": "Bearer abc"},
        {"authorization": "Basic dXNlcjpwdw=="},
        {"authorization": "Negotiate TlRMTVNTUAAB"},
        {"authorization": _negotiate_kerberos()},
        {"authorization": "Negotiate zzzz"},
        {"authorization": "Digest realm=x"},
        {"x-api-key": "k"},
        {},
    ):
        tags.add(detect_authentication(headers, "http://x"))

    interceptor = NetworkInterceptor()

    # A 401 relabels the request with the scheme the server demanded.
    for challenge in ("Basic realm=x", "Bearer", "NTLM", "Negotiate", "Digest realm=x"):
        request_data = {}
        interceptor._apply_auth_challenge({"www-authenticate": challenge}, request_data, {})
        tags.add(request_data["authentication"])

    # A 3xx handing off to an IdP relabels it "oauth".
    request_data = {}
    interceptor._apply_idp_redirect(
        {"location": "https://dev-1.okta.com/oauth2/v1/authorize"}, request_data, {}
    )
    tags.add(request_data["authentication"])

    # aggregate_by_origin's default for a request that never got a label at all.
    tags.add(aggregate_by_origin([{"url": "http://a.com/1"}])[0]["authentication"])

    return tags


def test_producers_emit_exactly_the_known_vocabulary():
    # Both directions matter: an unknown tag degrades to unknown/review, and a tag
    # nothing emits leaves dead entries in the two classifiers.
    assert _observed_tags() == SCRAPER_AUTH_TAGS


@pytest.mark.parametrize("tag", sorted(SCRAPER_AUTH_TAGS))
def test_tag_maps_to_its_own_auth_method(tag):
    assert tag_to_auth_method(tag) == AuthMethod(tag)


@pytest.mark.parametrize("tag", sorted(SCRAPER_AUTH_TAGS))
def test_tag_has_a_rank(tag):
    assert tag in _AUTH_RANK


def test_rank_table_has_no_tags_the_scraper_cannot_emit():
    # "unknown" is _auth_rank's fallback, not a tag any producer emits.
    assert set(_AUTH_RANK) - {"unknown"} == SCRAPER_AUTH_TAGS
