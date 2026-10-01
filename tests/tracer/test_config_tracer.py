"""Tests for config_tracer.py"""

import json
import logging
from urllib.parse import urlparse

import pytest

from config_tracer.models import (
    ConfigSource,
    Origin,
    ProbeResult,
    AuthMethod,
    HttpMethod,
    _VERDICT_PRECEDENCE,
    _OFFER_PREFERENCE,
)
from config_tracer.extract import (
    _clean_url,
    _classify_url,
    _partition_urls,
    extract_urls,
    extract_urls_from_text,
    strip_js_block_comments,
    sanitize_js_object,
    try_parse_json,
    urls_from_payload,
)
from config_tracer.capture import (
    _is_json_response,
    _exceeds_size_limit,
    process_network_captures,
    process_js_captures,
)
from config_tracer.crawl import crawl, _check_auth_signal
from config_tracer.probe import (
    _host_root_url,
    probe_urls,
    probe_urls_with_roots,
    build_auth_map,
    redirect_sources,
    synthesized_sources,
    _parse_www_authenticate,
    _challenge_schemes,
    _classify_probe,
)
from config_tracer.resolve import resolve_hosts
from config_tracer.report import _collapse_host_verdict, build_report


# ---------------------------------------------------------------------------
# Stub for Playwright Response objects
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, url="https://example.com", headers=None, status=200):
        self.url = url
        self.headers = headers or {}
        self.status = status


# ===========================================================================
# Part 1: Unit Tests — Pure Functions
# ===========================================================================


class TestCleanUrl:
    def test_no_trailing_punctuation(self):
        assert _clean_url("https://example.com/path") == "https://example.com/path"

    def test_trailing_period(self):
        assert _clean_url("https://example.com/path.") == "https://example.com/path"

    def test_trailing_comma(self):
        assert _clean_url("https://example.com/path,") == "https://example.com/path"

    def test_trailing_semicolon(self):
        assert _clean_url("https://example.com/path;") == "https://example.com/path"

    def test_trailing_colon(self):
        assert _clean_url("https://example.com/path:") == "https://example.com/path"

    def test_trailing_paren(self):
        assert _clean_url("https://example.com/path)") == "https://example.com/path"

    def test_trailing_backslash(self):
        assert _clean_url("https://example.com/path\\") == "https://example.com/path"


class TestClassifyUrl:
    def test_clean_url_returns_none(self):
        assert _classify_url("https://example.com/path") is None

    def test_template_flagged(self):
        assert _classify_url("https://${host}/path") == "template"

    def test_partial_template_flagged(self):
        assert _classify_url("https://${e") == "template"

    def test_backtick_flagged(self):
        assert _classify_url("https://example.com/`") == "template"

    def test_dollar_in_query_clean(self):
        # $ outside the hostname is fine — RFC 3986 sub-delim
        assert _classify_url("https://example.com/api?id=$1") is None

    def test_empty_host_flagged(self):
        assert _classify_url("http://") == "bad_host"

    def test_percent_in_host_flagged(self):
        assert _classify_url("https://www.%/path") == "bad_host"

    def test_underscore_in_host_flagged(self):
        # 'mock_section_url'-style placeholders
        assert _classify_url("https://mock_section_url/x") == "bad_host"

    def test_localhost_clean(self):
        assert _classify_url("http://localhost:8080/api") is None


class TestPartitionUrls:
    def test_split(self):
        clean, suspect = _partition_urls([
            "https://real.example.com/a",
            "https://${e}/b",
            "https://www.%/c",
            "https://other.example.com/d",
        ])
        assert clean == ["https://real.example.com/a", "https://other.example.com/d"]
        assert suspect == [
            ("https://${e}/b", "template"),
            ("https://www.%/c", "bad_host"),
        ]

    def test_all_clean(self):
        clean, suspect = _partition_urls(["https://a.example.com", "https://b.example.com"])
        assert len(clean) == 2 and suspect == []

    def test_all_suspect(self):
        clean, suspect = _partition_urls(["http://", "https://${x"])
        assert clean == []
        assert {r for _, r in suspect} == {"bad_host", "template"}


class TestExtractUrls:
    def test_string_with_url(self):
        result = extract_urls("https://api.example.com/v1")
        assert result == ["https://api.example.com/v1"]

    def test_string_without_url(self):
        assert extract_urls("just some text") == []

    def test_dict_with_urls(self):
        obj = {"api": "https://a.com", "cdn": "https://b.com"}
        result = extract_urls(obj)
        assert set(result) == {"https://a.com", "https://b.com"}

    def test_nested_dict(self):
        obj = {"outer": {"inner": "https://deep.com/api"}}
        result = extract_urls(obj)
        assert result == ["https://deep.com/api"]

    def test_list_of_strings(self):
        obj = ["https://a.com", "https://b.com"]
        result = extract_urls(obj)
        assert result == ["https://a.com", "https://b.com"]

    def test_mixed_nesting(self):
        obj = [{"urls": ["https://a.com"]}, "https://b.com"]
        result = extract_urls(obj)
        assert set(result) == {"https://a.com", "https://b.com"}

    def test_deduplication(self):
        obj = {"a": "https://dup.com", "b": "https://dup.com"}
        result = extract_urls(obj)
        assert result == ["https://dup.com"]

    def test_shared_seen_set(self):
        seen = set()
        r1 = extract_urls("https://shared.com", seen)
        r2 = extract_urls("https://shared.com", seen)
        assert r1 == ["https://shared.com"]
        assert r2 == []

    def test_integer_value_ignored(self):
        assert extract_urls(42) == []

    def test_none_value_ignored(self):
        assert extract_urls(None) == []


class TestExtractUrlsFromText:
    def test_single_url(self):
        result = extract_urls_from_text('config = "https://api.example.com"')
        assert result == ["https://api.example.com"]

    def test_multiple_urls(self):
        text = 'a: "https://a.com", b: "https://b.com", c: "http://c.com"'
        result = extract_urls_from_text(text)
        assert len(result) == 3

    def test_deduplication(self):
        text = "https://dup.com and https://dup.com again"
        result = extract_urls_from_text(text)
        assert result == ["https://dup.com"]

    def test_no_urls(self):
        assert extract_urls_from_text("nothing here") == []

    def test_url_with_query_string(self):
        text = "https://example.com/api?key=val&foo=bar"
        result = extract_urls_from_text(text)
        assert result == ["https://example.com/api?key=val&foo=bar"]


class TestStripJsBlockComments:
    def test_url_in_block_comment_removed(self):
        # The license-banner case that motivated this.
        text = '/*! bundled by webpack, https://reactjs.org */ var x = 1;'
        assert "https://reactjs.org" not in strip_js_block_comments(text)

    def test_multiline_license_banner_removed(self):
        text = (
            '/*!\n'
            '  * Bootstrap v5.3.7 (https://getbootstrap.com/)\n'
            '  * https://github.com/twbs/bootstrap/blob/main/LICENSE\n'
            '  */\n'
            'var api = "https://api.internal.corp/v1";'
        )
        out = strip_js_block_comments(text)
        assert "https://getbootstrap.com/" not in out
        assert "https://github.com/twbs/bootstrap/blob/main/LICENSE" not in out
        assert "https://api.internal.corp/v1" in out

    def test_url_in_string_kept(self):
        # The `//` in a real URL must never be read as a comment.
        text = 'var api = "https://api.internal.corp/v1";'
        assert "https://api.internal.corp/v1" in strip_js_block_comments(text)

    def test_double_slash_in_string_not_a_comment(self):
        text = "const u = 'http://a.corp/x'; const v = 'http://b.corp/y';"
        out = strip_js_block_comments(text)
        assert "http://a.corp/x" in out
        assert "http://b.corp/y" in out

    def test_block_comment_markers_in_string_kept(self):
        # `/*` and `*/` inside a string literal must not trigger comment stripping.
        text = 'var u = "https://real.corp/a/*b*/c";'
        assert "https://real.corp/a/*b*/c" in strip_js_block_comments(text)

    def test_url_next_to_slash_stripping_regex_survives(self):
        # A URL-normalizing regex with an escaped `//` sits in code; the real URL
        # that follows on the same (minified) line must survive. Block-only
        # stripping never touches `//`, so there's nothing to misfire.
        text = r'x.replace(/https?:\/\//g, "");var u="https://real.corp/api";'
        out = strip_js_block_comments(text)
        assert "https://real.corp/api" in out

    def test_line_comment_url_deliberately_kept(self):
        # `//` line comments are intentionally NOT stripped (see docstring);
        # stripping them safely needs regex disambiguation we don't attempt.
        text = 'var x = 1; // see https://docs.internal.corp/guide\n'
        assert "https://docs.internal.corp/guide" in strip_js_block_comments(text)

    def test_process_js_captures_ignores_banner_urls(self):
        body = (
            '/*! @license MIT https://cdn.jsdelivr.net/lib */\n'
            'var API = "https://api.internal.corp/v1";'
        )
        sources = process_js_captures([("https://app/bundle.js", body)])
        assert len(sources) == 1
        assert sources[0].urls_found == ["https://api.internal.corp/v1"]


class TestSanitizeJsObject:
    def test_line_comments(self):
        text = '{"a": 1 // comment\n}'
        result = json.loads(sanitize_js_object(text))
        assert result == {"a": 1}

    def test_block_comments(self):
        text = '{"a": 1 /* block comment */}'
        result = json.loads(sanitize_js_object(text))
        assert result == {"a": 1}

    def test_single_to_double_quotes(self):
        text = "{'a': 'b'}"
        result = json.loads(sanitize_js_object(text))
        assert result == {"a": "b"}

    def test_trailing_comma_object(self):
        text = '{"a": 1,}'
        result = json.loads(sanitize_js_object(text))
        assert result == {"a": 1}

    def test_trailing_comma_array(self):
        text = '[1, 2, 3,]'
        result = json.loads(sanitize_js_object(text))
        assert result == [1, 2, 3]

    def test_combined(self):
        text = "{'key': 'value', // comment\n}"
        result = json.loads(sanitize_js_object(text))
        assert result == {"key": "value"}


class TestTryParseJson:
    def test_valid_json(self):
        parsed, err = try_parse_json('{"key": "value"}')
        assert parsed == {"key": "value"}
        assert err is None

    def test_js_object(self):
        parsed, err = try_parse_json("{'key': 'value',}")
        assert parsed == {"key": "value"}
        assert err is None

    def test_unparseable(self):
        parsed, err = try_parse_json("not json at all")
        assert parsed is None
        assert err is not None


class TestUrlsFromPayload:
    ORIGIN = "network: https://cdn.com/config.json"

    def _warnings(self, caplog):
        return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]

    def test_parsed(self, caplog):
        with caplog.at_level(logging.WARNING, logger="config_tracer.extract"):
            urls = urls_from_payload('{"api": "https://api.com/v1"}', self.ORIGIN)
        assert urls == ["https://api.com/v1"]
        assert self._warnings(caplog) == []

    def test_unparseable_is_scraped_and_logged(self, caplog):
        with caplog.at_level(logging.WARNING, logger="config_tracer.extract"):
            urls = urls_from_payload('api_url = "https://api.com/v1"', self.ORIGIN)
        assert urls == ["https://api.com/v1"]
        [warning] = self._warnings(caplog)
        assert warning.startswith(
            "Could not parse network: https://cdn.com/config.json as JSON; "
            "regex-scraping it instead: ")

    def test_unparseable_logged_even_when_nothing_scraped(self, caplog):
        with caplog.at_level(logging.WARNING, logger="config_tracer.extract"):
            urls = urls_from_payload("not json at all", self.ORIGIN)
        assert urls == []
        assert len(self._warnings(caplog)) == 1


class TestProcessNetworkCaptures:
    def test_valid_json_with_urls(self):
        captured = [("https://cdn.com/config.json", '{"api": "https://api.com/v1"}')]
        result = process_network_captures(captured)
        assert len(result) == 1
        assert "https://api.com/v1" in result[0].urls_found

    def test_invalid_json_fallback(self):
        captured = [("https://cdn.com/broken.json", 'api_url = "https://api.com/v1"')]
        result = process_network_captures(captured)
        assert len(result) == 1
        assert "https://api.com/v1" in result[0].urls_found

    def test_no_urls_skipped(self):
        captured = [("https://cdn.com/data.json", '{"count": 42}')]
        result = process_network_captures(captured)
        assert len(result) == 0

    def test_multiple_captures(self):
        captured = [
            ("https://a.com/config.json", '{"url": "https://a.com/api"}'),
            ("https://b.com/config.json", '{"url": "https://b.com/api"}'),
        ]
        result = process_network_captures(captured)
        assert len(result) == 2


# ===========================================================================
# Part 2: Unit Tests with Mocks — Response Helpers
# ===========================================================================


class TestIsJsonResponse:
    def test_json_content_type(self):
        resp = FakeResponse(headers={"content-type": "application/json"})
        assert _is_json_response(resp) is True

    def test_json_content_type_with_charset(self):
        resp = FakeResponse(headers={"content-type": "application/json; charset=utf-8"})
        assert _is_json_response(resp) is True

    def test_html_content_type(self):
        resp = FakeResponse(headers={"content-type": "text/html"})
        assert _is_json_response(resp) is False

    def test_json_url_extension(self):
        resp = FakeResponse(url="https://cdn.com/config.json")
        assert _is_json_response(resp) is True

    def test_json_url_with_query(self):
        resp = FakeResponse(url="https://cdn.com/config.json?v=2")
        assert _is_json_response(resp) is True

    def test_non_json(self):
        resp = FakeResponse(
            url="https://cdn.com/data.xml",
            headers={"content-type": "text/plain"},
        )
        assert _is_json_response(resp) is False


class TestExceedsSizeLimit:
    def test_under_limit(self):
        resp = FakeResponse(headers={"content-length": "1000"})
        assert _exceeds_size_limit(resp) is False

    def test_over_limit(self):
        resp = FakeResponse(headers={"content-length": "10000000"})
        assert _exceeds_size_limit(resp) is True

    def test_no_header(self):
        resp = FakeResponse(headers={})
        assert _exceeds_size_limit(resp) is False

    def test_non_numeric(self):
        resp = FakeResponse(headers={"content-length": "unknown"})
        assert _exceeds_size_limit(resp) is False


# ===========================================================================
# Part 3: Integration Tests — Local HTTP Server + Playwright
# ===========================================================================


@pytest.mark.asyncio
async def test_full_crawl_finds_network_and_dom_sources(test_server):
    """Crawl the local test server and verify URLs from multiple strategies are found."""
    sources = await crawl(test_server, timeout=10000, wait_after_load=2000)

    all_urls = set()
    for src in sources:
        all_urls.update(src.urls_found)

    # Strategy A: <script type="application/json">
    assert "https://strategy-a.example.com/api" in all_urls

    # Strategy B: inline JS variable assignment
    assert "https://strategy-b.example.com/cdn" in all_urls

    # Network capture: /api/settings.json fetched by inline script
    assert "https://network.example.com/dashboard" in all_urls


@pytest.mark.asyncio
async def test_network_capture_skips_non_json(test_server):
    """Verify that non-JSON responses are not included in results."""
    sources = await crawl(test_server, timeout=10000, wait_after_load=2000)
    origins = [src.origin for src in sources]
    for origin in origins:
        assert "/not-json" not in origin


@pytest.mark.asyncio
async def test_report_from_crawl(test_server):
    """build_report places every crawled URL under the service that owns it."""
    sources = await crawl(test_server, timeout=10000, wait_after_load=2000)
    report = build_report(sources)

    assert isinstance(report.suspect_urls, list)
    # The report indexes by URL under its service: there is no forward array of
    # sources to walk, only the provenance hanging off each URL.
    assert len(report.services) > 0
    for svc in report.services:
        assert svc.urls
        for evidence in svc.urls:
            assert Origin.from_url(evidence.url) == svc.origin
            assert isinstance(evidence.sources, list)


@pytest.mark.asyncio
async def test_default_single_url_unchanged(test_server):
    """Without follow_links, the deep route and the cookie-gated API must NOT appear."""
    sources = await crawl(
        test_server,
        timeout=10000,
        wait_after_load=2000,
    )
    all_urls = {u for s in sources for u in s.urls_found}
    assert "https://deep-page.example.com/api" not in all_urls
    assert "https://protected-api.example.com/v1" not in all_urls


@pytest.mark.asyncio
async def test_manifest_probe_skips_spa_html_fallback(test_server):
    """SPA fallback (HTML body served at /manifest.json with 200) must not
    be captured as a manifest, and its embedded asset URLs must not surface."""
    sources = await crawl(
        test_server,
        timeout=10000,
        wait_after_load=2000,
    )
    for src in sources:
        assert "/manifest.json" not in src.origin
    all_urls = {u for s in sources for u in s.urls_found}
    spa_asset = f"{test_server}/assets/img/spa-fallback-image.avif"
    assert spa_asset not in all_urls


@pytest.mark.asyncio
async def test_manifest_probe_finds_lazy_chunk_url(test_server):
    """Manifest probe should fetch chunk-admin.js even though no page links to it."""
    sources = await crawl(
        test_server,
        timeout=10000,
        wait_after_load=2000,
    )
    all_urls = {u for s in sources for u in s.urls_found}
    assert "https://chunk-admin.example.com/api" in all_urls


@pytest.mark.asyncio
async def test_follow_links_finds_deep_route(test_server):
    """With follow_links=True the crawler should discover /deep and capture its config."""
    sources = await crawl(
        test_server,
        timeout=10000,
        wait_after_load=2000,
        follow_links=True,
        max_pages=3,
    )
    all_urls = {u for s in sources for u in s.urls_found}
    assert "https://deep-page.example.com/api" in all_urls


@pytest.mark.asyncio
async def test_interaction_triggers_xhr(test_server):
    """The click-only fetch should be captured (interactions always run)."""
    sources = await crawl(
        test_server,
        timeout=10000,
        wait_after_load=2000,
        interact_budget_ms=6000,
    )
    all_urls = {u for s in sources for u in s.urls_found}
    assert "https://click-triggered.example.com/api" in all_urls


# ===========================================================================
# Part 4: Auth Detection — Unit Tests
# ===========================================================================


class TestParseWwwAuthenticate:
    # Returns a bare AuthMethod; the caller keeps the raw header beside it, which
    # carries everything the verdict elides. StrEnum members compare equal to
    # their string value, so the bare-string asserts below double as a check on
    # that contract.
    def test_basic(self):
        assert _parse_www_authenticate('Basic realm="test"') == "basic"

    def test_bearer(self):
        assert _parse_www_authenticate("Bearer") == "bearer"

    def test_negotiate(self):
        assert _parse_www_authenticate("Negotiate") == "negotiate"

    def test_unrecognized_scheme_is_other(self):
        # An uncommon scheme collapses to OTHER; the specific name survives as
        # the first token of the raw header, which the caller keeps on
        # ProbeResult.www_authenticate.
        assert _parse_www_authenticate("Digest realm=x") == "other"

    def test_empty_is_unknown(self):
        assert _parse_www_authenticate("") == "unknown"

    def test_whitespace_only_is_unknown(self):
        # Truthy but tokenless — the case the old `scheme or "unknown"` swallowed.
        # UNKNOWN paired with a kept www_authenticate is unique to this case.
        assert _parse_www_authenticate("   ") == "unknown"

    def test_params_without_a_scheme_is_unknown(self):
        # Malformed: params but no scheme to attach them to. Nothing to rank, so
        # the verdict is UNKNOWN and the raw header carries the oddity onward
        # for whoever reads the report.
        assert _parse_www_authenticate('realm="x"') == "unknown"


class TestChallengeSchemes:
    # _challenge_schemes is where the two comma meanings are told apart: commas
    # separate challenges, but they also separate the auth-params *within* one
    # challenge. Getting this wrong in either direction is a silent wrong
    # verdict, so each shape is pinned separately.
    def test_single_challenge(self):
        assert _challenge_schemes('Basic realm="test"') == ["basic"]

    def test_two_bare_schemes(self):
        assert _challenge_schemes("Negotiate, NTLM") == ["negotiate", "ntlm"]

    def test_no_space_after_comma(self):
        assert _challenge_schemes("Negotiate,NTLM") == ["negotiate", "ntlm"]

    def test_params_do_not_open_a_new_challenge(self):
        # One Digest offer, not three. `qop=` and `nonce=` continue it.
        assert _challenge_schemes(
            'Digest realm="x", qop="auth", nonce="abc"') == ["digest"]

    def test_scheme_after_a_parameterized_challenge(self):
        # The hard middle case: the first challenge carries a param and the
        # second is bare, so the same comma depth holds both meanings.
        assert _challenge_schemes(
            'Basic realm="x", Bearer') == ["basic", "bearer"]

    def test_comma_inside_a_quoted_param_value(self):
        # realm="a,b" is one param. Splitting on every comma would read `b"` as
        # a scheme and invent an offer the server never made.
        assert _challenge_schemes('Digest realm="a,b", qop="auth"') == ["digest"]

    def test_bws_around_param_equals(self):
        # RFC 9110 allows whitespace around `=`. Judging a piece by whether its
        # first *token* contains `=` would read `realm = "x"` as a scheme name.
        assert _challenge_schemes(
            'Bearer realm = "x", error = "invalid_token"') == ["bearer"]

    def test_token68_is_not_a_param(self):
        # A Negotiate blob ends in `=` padding, but it is a token68 following
        # the scheme, not a `key=value` param.
        assert _challenge_schemes(
            "Negotiate YIIZ3AYGKwYBBQUCoIIZ0DCCGcw=") == ["negotiate"]

    def test_empty_pieces_are_skipped(self):
        assert _challenge_schemes("Basic,,Bearer") == ["basic", "bearer"]


class TestMultiChallengeVerdict:
    # A response's challenges are an offer to choose from, not a set of demands
    # to satisfy — so the verdict is the *best* scheme available, by
    # _OFFER_PREFERENCE. This is the opposite reduction to the one
    # _collapse_host_verdict runs across a service's URLs, and the two are
    # pinned against each other in TestOfferVsVerdictOrdering below.
    def test_bearer_beside_basic_is_bearer(self):
        # The case that decides the direction: this URL is exposable on Bearer,
        # and the Basic it also accepts costs nothing because nothing has to use
        # it. Reporting `basic` would flag a blocker the F5 declines to pick.
        assert _parse_www_authenticate("Bearer, Basic") == "bearer"

    def test_negotiate_beside_ntlm_is_negotiate(self):
        # IIS's default offer. NEGOTIATE is the honest verdict — "needs review",
        # since SPNEGO may resolve to Kerberos (exposable) or fall back to NTLM
        # (blocker) — and that ambiguity is exactly what the verdict encodes.
        assert _parse_www_authenticate("Negotiate, NTLM") == "negotiate"

    def test_verdict_does_not_depend_on_server_ordering(self):
        # Convention puts the strongest scheme first, so taking the leading
        # token usually lands here too — but on the server's ordering rather
        # than ours. Either order, same answer.
        assert (_parse_www_authenticate("Negotiate, NTLM")
                == _parse_www_authenticate("NTLM, Negotiate")
                == "negotiate")

    def test_three_way_offer_takes_the_best(self):
        assert _parse_www_authenticate(
            'Negotiate, NTLM, Basic realm="corp"') == "negotiate"

    def test_known_scheme_beats_the_catch_all(self):
        # OTHER is last resort, not second choice: we would take the Basic we
        # know how to proxy over gambling on an unrecognized scheme, even though
        # OTHER outranks BASIC on *risk*. The safe default inverts here.
        assert _parse_www_authenticate(
            'Digest realm="x", Basic realm="y"') == "basic"

    def test_unusable_offer_names_the_informative_blocker(self):
        # Neither is usable. NTLM still wins over OTHER because it says *why*
        # exposure fails — connection-bound auth against a reusing proxy —
        # where OTHER only says we do not recognize the scheme.
        assert _parse_www_authenticate("Digest, NTLM") == "ntlm"

    def test_single_challenge_verdict_is_unchanged(self):
        # The parameterized single-challenge forms already worked; they must
        # keep working now that the value is walked rather than tokenized once.
        assert _parse_www_authenticate(
            'Bearer realm="x", error="invalid_token"') == "bearer"


class TestOfferVsVerdictOrdering:
    """The two reductions are deliberately opposed; pin the relationship so a
    later edit to one ordering cannot silently drift from the other."""

    def test_offer_preference_covers_every_challenge_scheme(self):
        # Anything _parse_www_authenticate can produce from a challenge has to
        # be rankable, or the verdict would fall through to UNKNOWN.
        assert set(_OFFER_PREFERENCE) == {
            AuthMethod.BASIC, AuthMethod.BEARER, AuthMethod.NEGOTIATE,
            AuthMethod.NTLM, AuthMethod.OTHER,
        }

    def test_known_schemes_are_the_risk_order_reversed(self):
        # For the four schemes whose risk is actually known, preferring the best
        # of an offer is exactly the inverse of fearing the worst of a service.
        known = [m for m in _OFFER_PREFERENCE if m is not AuthMethod.OTHER]
        risk = [m for m in _VERDICT_PRECEDENCE if m in set(known)]
        assert known == list(reversed(risk))

    def test_other_is_last_resort_not_a_mirror_of_its_risk_rank(self):
        # The one member that does not survive the flip. OTHER sits third on
        # risk (a safe default about an unknown) but last on preference: we
        # would never claim to pick the scheme we just called unsupported.
        assert _OFFER_PREFERENCE[-1] is AuthMethod.OTHER
        assert _VERDICT_PRECEDENCE.index(AuthMethod.OTHER) <             _VERDICT_PRECEDENCE.index(AuthMethod.NEGOTIATE)


class TestClassifyProbe:
    # _classify_probe returns a bare AuthMethod verdict. StrEnum members compare
    # equal to their string value, so the bare-string asserts below hold.
    def test_401_with_basic(self):
        assert _classify_probe(401, 'Basic realm="x"') == "basic"

    def test_401_without_header_is_unknown(self):
        # Bare 401 = auth required, scheme undisclosed. It needs no marker of its
        # own: the (401, unknown, no www_authenticate) triple is unique to it.
        assert _classify_probe(401, None) == "unknown"

    def test_403_with_bearer_challenge(self):
        # RFC 6750 insufficient_scope: 403 carries a Bearer challenge, which
        # must win over the bare unknown verdict a plain 403 would get.
        assert _classify_probe(403, 'Bearer error="insufficient_scope"') == "bearer"

    # The coarse 4xx statuses all mean "we learned nothing about auth", and no
    # longer have arms of their own — they fall through to the same UNKNOWN as
    # everything unhandled. Each is still asserted, so the collapse can't quietly
    # start reclassifying one of them.
    def test_403_without_header_is_unknown(self):
        assert _classify_probe(403, None) == "unknown"

    def test_400_is_unknown(self):
        assert _classify_probe(400, None) == "unknown"

    def test_404_is_unknown(self):
        assert _classify_probe(404, None) == "unknown"

    def test_407_is_unknown(self):
        assert _classify_probe(407, None) == "unknown"

    def test_5xx_is_unknown(self):
        # A 5xx is a successful HTTP transaction that says nothing about auth.
        # `status_code` is emitted beside the verdict, so a reader who needs to
        # tell a 503 from a stale 404 still can.
        assert _classify_probe(503, None) == "unknown"
        assert _classify_probe(500, None) == "unknown"

    def test_200_with_header(self):
        # A challenge on any status is authoritative (RFC 7235 §4.1 MAY clause).
        assert _classify_probe(200, "Negotiate") == "negotiate"

    def test_200_without_header(self):
        assert _classify_probe(200, None) == "unauthenticated"

    def test_3xx_offhost_with_keyword_is_oauth(self):
        # Redirect off-host to an IdP whose URL carries an auth keyword:
        # federated SSO/OAuth, the strongest signal.
        assert _classify_probe(
            302, None,
            "https://login.microsoftonline.com/authorize?client_id=x",
            "https://app.example.com/api",
        ) == "oauth"

    def test_3xx_samehost_with_keyword_is_login_redirect(self):
        # Same-origin redirect to a login path is local form auth, not OAuth.
        assert _classify_probe(
            302, None,
            "https://app.example.com/login",
            "https://app.example.com/dashboard",
        ) == "login_redirect"

    def test_3xx_relative_location_with_keyword_is_login_redirect(self):
        # A relative "Location: /login" resolves to the same host once joined.
        assert _classify_probe(
            302, None, "/login", "https://app.example.com/dashboard",
        ) == "login_redirect"

    def test_3xx_offhost_without_keyword_is_unknown(self):
        # Off-host redirect with no auth hint isn't an auth method, and needs no
        # marker either: off-origin can only fire on an absolute Location, so the
        # host such a marker would name is already in ProbeResult.location.
        assert _classify_probe(
            302, None,
            "https://cdn.othercorp.com/assets",
            "https://app.example.com/static",
        ) == "unknown"

    def test_3xx_samehost_without_keyword_is_unknown(self):
        # A plain same-origin route change needs nothing more: ProbeResult.location
        # keeps the target verbatim, so any gloss would only repeat the record.
        assert _classify_probe(
            302, None,
            "https://app.example.com/new-path",
            "https://app.example.com/old-path",
        ) == "unknown"

    def test_3xx_relative_location_without_keyword_is_unknown(self):
        assert _classify_probe(
            302, None, "/new-path", "https://app.example.com/old-path",
        ) == "unknown"

    def test_3xx_host_comparison_is_case_insensitive(self):
        # Differing host casing must not be mistaken for an off-host redirect.
        # Checked through a login target, where the comparison is observable:
        # same-origin is a local form login, off-origin would be federated OAuth.
        assert _classify_probe(
            302, None,
            "https://APP.example.com/login",
            "https://app.example.com/old-path",
        ) == "login_redirect"

    def test_3xx_no_location_is_unknown(self):
        # A redirect that named no target is legible as-is: 3xx with no
        # `location` in the record is that case and nothing else, since any
        # Location we did get is kept verbatim.
        assert _classify_probe(302, None, "", "https://app.example.com/x") == "unknown"


# ===========================================================================
# Part 5: Auth Detection — Probing Integration Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_probe_basic_auth(auth_server):
    results = await probe_urls([f"{auth_server}/auth/basic"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 401
    assert results[0].detected_method == "basic"
    assert results[0].www_authenticate is not None
    # No Location on a non-redirect: absent is None, not "".
    assert results[0].location is None
    # The HEAD was answered, so no GET was sent.
    assert results[0].http_method is HttpMethod.HEAD


@pytest.mark.asyncio
async def test_probe_falls_back_to_get_on_405(auth_server):
    """A path that refuses HEAD is probed again with GET, and the result says
    so: the verdict is read off the GET's answer, a challenge the HEAD never
    reached."""
    results = await probe_urls([f"{auth_server}/auth/get-only"], timeout=5.0)
    assert len(results) == 1
    assert results[0].http_method is HttpMethod.GET
    assert results[0].status_code == 401
    assert results[0].detected_method is AuthMethod.BASIC


@pytest.mark.asyncio
async def test_probe_names_the_request_a_transport_error_came_from(monkeypatch):
    """The HEAD failing and the GET after a 405 failing leave the same error
    and verdict; only `http_method` tells them apart."""
    async def fake_send(session, method, url, timeout):
        if url == "https://svc.corp/after-405" and method is HttpMethod.HEAD:
            return 405, None, ""
        raise TimeoutError  # what aiohttp's total timeout raises

    monkeypatch.setattr("config_tracer.probe._send", fake_send)
    results = await probe_urls(["https://svc.corp/head", "https://svc.corp/after-405"])
    assert [(r.http_method, r.detected_method, r.error) for r in results] == [
        (HttpMethod.HEAD, AuthMethod.NO_RESPONSE, "timeout"),
        (HttpMethod.GET, AuthMethod.NO_RESPONSE, "timeout"),
    ]


@pytest.mark.asyncio
async def test_probe_bearer_auth(auth_server):
    results = await probe_urls([f"{auth_server}/auth/bearer"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 401
    assert results[0].detected_method == "bearer"


@pytest.mark.asyncio
async def test_probe_repeated_challenge_headers(auth_server):
    """A server offering several schemes on separate header lines."""
    results = await probe_urls([f"{auth_server}/auth/multi-header"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 401
    # The offer is ours to choose from, so the verdict is the best of it.
    assert results[0].detected_method == "negotiate"
    # The point of the fix is here rather than in the verdict: aiohttp keeps
    # repeats as separate entries and .get() returns only the first, so without
    # reading every line the NTLM and Basic this server also accepts would be
    # absent from the report entirely — and those are what an operator needs in
    # order to disagree with the verdict.
    assert results[0].www_authenticate == 'Negotiate, NTLM, Basic realm="corp"'


@pytest.mark.asyncio
async def test_probe_inline_challenge_list(auth_server):
    """The same offer as one comma-separated value.

    RFC 9110 §5.3 makes the repeated and comma-joined forms equivalent, so the
    two must not reach different verdicts."""
    results = await probe_urls([f"{auth_server}/auth/multi-inline"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 401
    assert results[0].detected_method == "negotiate"
    assert results[0].www_authenticate == "Negotiate, NTLM"


@pytest.mark.asyncio
async def test_probe_no_auth(auth_server):
    results = await probe_urls([f"{auth_server}/auth/none"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 200
    assert results[0].detected_method == "unauthenticated"


@pytest.mark.asyncio
async def test_probe_forbidden_keeps_verdict_and_probes_root(auth_server):
    """403 with no challenge keeps its own (unknown) verdict; the host root is
    probed separately and returned as an independent result, not substituted."""
    path_probes, root_probes = await probe_urls_with_roots(
        [f"{auth_server}/auth/forbidden"], timeout=5.0)
    assert len(path_probes) == 1
    assert path_probes[0].status_code == 403          # NOT overwritten by root
    assert path_probes[0].detected_method == "unknown"
    # root (/) returns 200 -> unauthenticated, kept as a separate synthesized probe
    assert len(root_probes) == 1
    assert root_probes[0].url == f"{auth_server}/"
    assert root_probes[0].status_code == 200
    assert root_probes[0].detected_method == "unauthenticated"
    # ...whose provenance is the path that set it off.
    assert synthesized_sources(path_probes, root_probes) == [ConfigSource(
        origin=f"synthesized: {auth_server}/auth/forbidden",
        urls_found=[f"{auth_server}/"])]


@pytest.mark.asyncio
async def test_root_probe_does_not_cross_origins(auth_server, gated_auth_server):
    """Two ports on one hostname are two services, each with its own front door,
    and each must be probed. Deduplicating the roots by bare hostname would probe
    whichever came first and let it stand for the whole box — reporting a front
    door for a service that was never probed that way, the cross-origin merge
    Origin exists to prevent in the report."""
    open_root = f"{auth_server}/auth/forbidden"          # this origin's / is 200
    gated_root = f"{gated_auth_server}/auth/forbidden"   # this origin's / is 401 Basic

    # Same host, different ports — indistinguishable to a hostname-keyed match.
    assert urlparse(open_root).hostname == urlparse(gated_root).hostname
    assert urlparse(open_root).port != urlparse(gated_root).port

    path_probes, root_probes = await probe_urls_with_roots(
        [open_root, gated_root], timeout=5.0)

    # Both front doors were probed, as two separate services, each keeping its
    # own verdict rather than one standing in for the other.
    assert {r.url: r.detected_method for r in root_probes} == {
        f"{auth_server}/": AuthMethod.UNAUTHENTICATED,
        f"{gated_auth_server}/": AuthMethod.BASIC,
    }
    # Neither path was rewritten from a root.
    assert {p.detected_method for p in path_probes} == {AuthMethod.UNKNOWN}


@pytest.mark.asyncio
async def test_probe_forbidden_with_bearer_challenge(auth_server):
    """403 carrying a Bearer challenge (RFC 6750 insufficient_scope) must keep
    that challenge — the root fallback must NOT overwrite it with the host
    root's 200/unauthenticated."""
    results = await probe_urls([f"{auth_server}/auth/forbidden-bearer"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 403
    assert results[0].detected_method == "bearer"
    assert results[0].www_authenticate is not None


@pytest.mark.asyncio
async def test_probe_deduplicates_urls(auth_server):
    url = f"{auth_server}/auth/none"
    results = await probe_urls([url, url, url], timeout=5.0)
    assert len(results) == 1


@pytest.mark.asyncio
async def test_probe_unreachable_url():
    results = await probe_urls(["http://192.0.2.1:1/nonexistent"], timeout=1.0)
    assert len(results) == 1
    assert results[0].status_code is None
    assert results[0].detected_method is AuthMethod.NO_RESPONSE
    assert results[0].error is not None


@pytest.mark.asyncio
async def test_probe_bad_request_probes_root(auth_server):
    """400 (rejected before auth could be read) triggers a root probe so the
    host's front door is still mapped. The path keeps its own verdict — the
    root's is reported separately, as its own result."""
    path_probes, root_probes = await probe_urls_with_roots(
        [f"{auth_server}/auth/bad-request"], timeout=5.0)
    assert path_probes[0].status_code == 400
    assert path_probes[0].detected_method == "unknown"
    # root probed, front door learned as an independent fact
    # (/ is open -> unauthenticated)
    assert len(root_probes) == 1
    assert root_probes[0].url.endswith("/")
    assert root_probes[0].detected_method == "unauthenticated"


@pytest.mark.asyncio
async def test_probe_not_found_no_root_probe(auth_server):
    """404 is a dead path -> no root probe, verdict kept."""
    path_probes, root_probes = await probe_urls_with_roots(
        [f"{auth_server}/auth/not-found"], timeout=5.0)
    assert path_probes[0].status_code == 404
    assert path_probes[0].detected_method == "unknown"
    assert root_probes == []


@pytest.mark.asyncio
async def test_probe_redirect(auth_server):
    results = await probe_urls([f"{auth_server}/auth/redirect"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 301
    # A plain same-host redirect with no auth hint isn't an auth method — it's
    # "unknown", and the target is the raw Location, not a gloss on it.
    assert results[0].detected_method == "unknown"
    assert results[0].location == "/somewhere-else"


@pytest.mark.asyncio
async def test_probe_redirect_to_login(auth_server):
    # Relative, same-host redirect to a login path: local form auth.
    results = await probe_urls([f"{auth_server}/auth/redirect-login"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 302
    assert results[0].detected_method == "login_redirect"
    # The verdict says "local form auth"; only the header says which door.
    assert results[0].location == "/oauth/authorize?client_id=abc"


@pytest.mark.asyncio
async def test_probe_redirect_to_idp(auth_server):
    # Off-host redirect to an external IdP: federated SSO/OAuth.
    results = await probe_urls([f"{auth_server}/auth/redirect-idp"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 302
    assert results[0].detected_method == "oauth"
    # The point of keeping the header: "oauth" alone can't tell an external IdP
    # from an ADFS box on the estate, and that difference decides the exposure.
    assert results[0].location == (
        "https://login.microsoftonline.com/authorize?client_id=abc")


@pytest.mark.asyncio
async def test_probe_server_error(auth_server):
    results = await probe_urls([f"{auth_server}/auth/server-error"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 500
    # 5xx is inconclusive for auth. `status_code` is what tells it apart from a
    # stale 404, and it is already in the record.
    assert results[0].detected_method == "unknown"


class TestHostRootUrl:
    def test_url_with_path(self):
        assert _host_root_url("https://api.example.com/v1/data") == "https://api.example.com/"

    def test_url_with_port(self):
        assert _host_root_url("http://localhost:8080/api/v1") == "http://localhost:8080/"

    def test_url_root_only(self):
        assert _host_root_url("https://api.example.com/") is None

    def test_url_no_path(self):
        assert _host_root_url("https://api.example.com") is None


class TestOrigin:
    """Origin.from_url is the service identity: scheme, lowercased host, and the
    effective port. `key` renders it as scheme://host[:port]."""

    def test_strips_path_and_query(self):
        assert Origin.from_url("https://h.example.com/v1/data?x=1") == Origin("https", "h.example.com", 443)

    def test_default_https_port_is_the_effective_port(self):
        # The bare origin and the explicit default port name one service, and
        # both carry 443 rather than "unspecified": no consumer has to know the
        # defaults.
        assert (Origin.from_url("https://h.example.com:443/x")
                == Origin.from_url("https://h.example.com/x")
                == Origin("https", "h.example.com", 443))

    def test_default_http_port_is_the_effective_port(self):
        assert Origin.from_url("http://h.example.com:80/x") == Origin("http", "h.example.com", 80)

    def test_non_default_port_kept(self):
        assert Origin.from_url("https://h.example.com:8080/x") == Origin("https", "h.example.com", 8080)

    def test_scheme_distinguishes(self):
        assert Origin.from_url("http://h.example.com/x") != Origin.from_url("https://h.example.com/x")

    def test_host_lowercased(self):
        assert Origin.from_url("https://H.Example.COM/x") == Origin("https", "h.example.com", 443)

    def test_no_host_returns_none(self):
        assert Origin.from_url("not-a-url") is None

    def test_non_http_scheme_returns_none(self):
        # The dependency map is of HTTP services; nothing else has an origin.
        assert Origin.from_url("myapp://open") is None
        assert Origin.from_url("ftp://files.example.com/x") is None

    def test_out_of_range_port_treated_as_unspecified(self):
        # Accessing urlparse(...).port raises on a 99999 port; we swallow it.
        assert Origin.from_url("http://h.example.com:99999/x") == Origin("http", "h.example.com", 80)

    def test_key_elides_the_default_port(self):
        assert Origin("https", "h.example.com", 443).key == "https://h.example.com"
        assert Origin("http", "h.example.com", 80).key == "http://h.example.com"
        assert Origin("https", "h.example.com", 8080).key == "https://h.example.com:8080"
        assert Origin("http", "h.example.com", 443).key == "http://h.example.com:443"

    def test_sort_key_groups_a_host_by_port(self):
        origins = [
            Origin("https", "b.example.com", 443),
            Origin("https", "a.example.com", 8080),
            Origin("http", "a.example.com", 80),
            Origin("https", "a.example.com", 443),
        ]
        assert sorted(origins, key=lambda o: o.sort_key) == [
            Origin("http", "a.example.com", 80),
            Origin("https", "a.example.com", 443),
            Origin("https", "a.example.com", 8080),
            Origin("https", "b.example.com", 443),
        ]


@pytest.mark.asyncio
async def test_probe_subpath_400_probes_root(auth_server):
    """A 400 on a deep path triggers a probe of the host root (not the path's own
    parent) so the front door is mapped; the path keeps its own verdict."""
    path_probes, root_probes = await probe_urls_with_roots(
        [f"{auth_server}/api-gated/v1/data"], timeout=5.0)
    assert path_probes[0].status_code == 400
    assert path_probes[0].detected_method == "unknown"
    assert len(root_probes) == 1
    assert root_probes[0].url == f"{auth_server}/"


@pytest.mark.asyncio
async def test_probe_no_root_probe_when_root_only(auth_server):
    """When the URL is already the host root, there's no higher root to consult
    — _host_root_url returns None, so no root probe is synthesized."""
    assert _host_root_url(f"{auth_server}/") is None


@pytest.mark.asyncio
async def test_probe_drops_root_that_gave_no_response(monkeypatch):
    """A root probe that got no response discloses nothing about the front
    door, so it is dropped like an UNKNOWN one rather than reported."""
    calls = []

    async def fake_probe_urls(urls, **kw):
        calls.append(list(urls))
        if urls == ["https://svc.corp/"]:
            return [ProbeResult(url="https://svc.corp/", http_method=HttpMethod.HEAD,
                                status_code=None, www_authenticate=None,
                                detected_method=AuthMethod.NO_RESPONSE, error="timeout")]
        return [ProbeResult(url=u, http_method=HttpMethod.HEAD, status_code=403,
                            www_authenticate=None, detected_method=AuthMethod.UNKNOWN)
                for u in urls]

    monkeypatch.setattr("config_tracer.probe.probe_urls", fake_probe_urls)
    path_probes, root_probes = await probe_urls_with_roots(["https://svc.corp/api"])

    assert calls == [["https://svc.corp/api"], ["https://svc.corp/"]]
    assert [p.url for p in path_probes] == ["https://svc.corp/api"]
    assert root_probes == []


def test_collapse_unknown_outranks_unauthenticated():
    """An open endpoint (often the host root) must never mask a locked-but-
    undisclosed sibling in the host headline; a concrete scheme still wins."""
    assert _collapse_host_verdict(
        {AuthMethod.UNKNOWN, AuthMethod.UNAUTHENTICATED}) == AuthMethod.UNKNOWN
    assert _collapse_host_verdict(
        {AuthMethod.BASIC, AuthMethod.UNKNOWN,
         AuthMethod.UNAUTHENTICATED}) == AuthMethod.BASIC


def test_collapse_no_response_ranks_between_unknown_and_unauthenticated():
    """A URL that gave no response must not let an open sibling headline the
    service as exposable, but every other verdict, UNKNOWN included, outranks
    it: within one tier a real response beats none."""
    assert _collapse_host_verdict(
        {AuthMethod.NO_RESPONSE, AuthMethod.UNAUTHENTICATED}) == AuthMethod.NO_RESPONSE
    assert _collapse_host_verdict(
        {AuthMethod.NO_RESPONSE, AuthMethod.UNKNOWN}) == AuthMethod.UNKNOWN
    assert _collapse_host_verdict(
        {AuthMethod.NO_RESPONSE, AuthMethod.BEARER}) == AuthMethod.BEARER


def test_collapse_dns_failed_ranks_between_no_response_and_unauthenticated():
    """DNS_FAILED never shares a service with another verdict, since DNS fails
    per host, but it needs a rank all the same: a method missing from the
    precedence would collapse to None. It sits in NO_RESPONSE's tier, below it,
    because no response still beats no address."""
    assert set(_VERDICT_PRECEDENCE) == set(AuthMethod)
    assert _collapse_host_verdict({AuthMethod.DNS_FAILED}) == AuthMethod.DNS_FAILED
    assert _collapse_host_verdict(
        {AuthMethod.DNS_FAILED, AuthMethod.UNAUTHENTICATED}) == AuthMethod.DNS_FAILED
    assert _collapse_host_verdict(
        {AuthMethod.DNS_FAILED, AuthMethod.NO_RESPONSE}) == AuthMethod.NO_RESPONSE


def test_collapse_ranks_by_blocker_risk():
    """The headline is the worst thing found across a service's URLs, not the
    most informative one: hard blockers (ntlm/basic/other) outrank the
    needs-review tier (negotiate), which outranks the exposable schemes."""
    # A blocker is never masked by a scheme that would pass exposure review.
    assert _collapse_host_verdict(
        {AuthMethod.NTLM, AuthMethod.NEGOTIATE}) == AuthMethod.NTLM
    assert _collapse_host_verdict(
        {AuthMethod.BASIC, AuthMethod.BEARER,
         AuthMethod.NEGOTIATE}) == AuthMethod.BASIC
    assert _collapse_host_verdict(
        {AuthMethod.OTHER, AuthMethod.BEARER}) == AuthMethod.OTHER
    # Needs-review outranks known-good, so an ambiguous negotiate isn't hidden
    # behind a bearer sibling.
    assert _collapse_host_verdict(
        {AuthMethod.NEGOTIATE, AuthMethod.BEARER,
         AuthMethod.LOGIN_REDIRECT}) == AuthMethod.NEGOTIATE
    # A concrete exposable verdict still beats the inconclusive catch-all, which
    # is dominated by 404s from stale config URLs.
    assert _collapse_host_verdict(
        {AuthMethod.BEARER, AuthMethod.UNKNOWN}) == AuthMethod.BEARER


def test_collapse_blocks_on_one_bad_url_though_an_offer_would_not():
    """The conjunction/disjunction contrast, in the two shapes it arrives in.

    A service whose one URL takes only Bearer and whose other takes only NTLM is
    blocked: exposing the service means exposing both, and the NTLM path has no
    other scheme to fall back to. A *single* URL offering both is not blocked —
    the F5 picks Bearer and the NTLM goes unused. Same two schemes, opposite
    answers, because one set has to be satisfied and the other only chosen
    from."""
    assert _collapse_host_verdict(
        {AuthMethod.BEARER, AuthMethod.NTLM}) == AuthMethod.NTLM
    assert _parse_www_authenticate("Bearer, NTLM") == AuthMethod.BEARER


def test_build_auth_map_inserts_root_probes():
    """A probed root that no config referenced is inserted as an entry of its
    own, alongside the path probes, which keep their own verdicts."""
    path = ProbeResult(url="https://h/x", http_method=HttpMethod.HEAD, status_code=401,
                       www_authenticate=None, detected_method=AuthMethod.UNKNOWN)
    root = ProbeResult(url="https://h/", http_method=HttpMethod.HEAD, status_code=200,
                       www_authenticate=None, detected_method=AuthMethod.UNAUTHENTICATED)
    auth_map = build_auth_map([path], [root])
    assert auth_map["https://h/x"].probe_result is path
    assert auth_map["https://h/"].probe_result is root


def test_build_auth_map_path_probe_beats_root_probe():
    """A root also probed as a path keeps that OWN probe. One
    probe_urls_with_roots call won't hand back both for one URL, but across the
    pipeline's hops a root one hop synthesized can be another's config URL or
    redirect target."""
    path = ProbeResult(url="https://h/", http_method=HttpMethod.HEAD, status_code=401,
                       www_authenticate="Basic", detected_method=AuthMethod.BASIC)
    root = ProbeResult(url="https://h/", http_method=HttpMethod.HEAD, status_code=200,
                       www_authenticate=None, detected_method=AuthMethod.UNAUTHENTICATED)
    auth_map = build_auth_map([path], [root])
    assert auth_map["https://h/"].probe_result is path


def _probe(url, status, method=AuthMethod.UNKNOWN):
    return ProbeResult(url=url, http_method=HttpMethod.HEAD, status_code=status,
                       www_authenticate=None, detected_method=method)


class TestSynthesizedSources:
    """synthesized_sources names each kept host root after the paths that set
    it off: its provenance is `synthesized: <path>`, never empty."""

    def test_every_triggering_path_names_the_root_in_probe_order(self):
        paths = [_probe("https://h/b", 403), _probe("https://h/a", 401),
                 _probe("https://h/c", 400)]
        root = _probe("https://h/", 200, AuthMethod.UNAUTHENTICATED)
        assert synthesized_sources(paths, [root]) == [
            ConfigSource(origin="synthesized: https://h/b", urls_found=["https://h/"]),
            ConfigSource(origin="synthesized: https://h/a", urls_found=["https://h/"]),
            ConfigSource(origin="synthesized: https://h/c", urls_found=["https://h/"]),
        ]

    def test_a_sibling_that_did_not_trigger_names_nothing(self):
        # Same root, but a readable, dead or scheme-naming path would not have
        # set it off.
        paths = [_probe("https://h/x", 401),
                 _probe("https://h/open", 200, AuthMethod.UNAUTHENTICATED),
                 _probe("https://h/gone", 404),
                 _probe("https://h/basic", 401, AuthMethod.BASIC),
                 _probe("https://h/down", None, AuthMethod.NO_RESPONSE)]
        root = _probe("https://h/", 401, AuthMethod.NTLM)
        assert [s.origin for s in synthesized_sources(paths, [root])] == [
            "synthesized: https://h/x"]

    def test_a_dropped_root_gets_no_source(self):
        # probe_urls_with_roots dropped the root (UNKNOWN / NO_RESPONSE), so it
        # is not reported, and must not be named either.
        assert synthesized_sources([_probe("https://h/x", 403)], []) == []

    def test_a_path_names_only_its_own_origins_root(self):
        paths = [_probe("https://h/x", 403), _probe("https://h:8443/y", 403)]
        root = _probe("https://h:8443/", 401, AuthMethod.BASIC)
        assert synthesized_sources(paths, [root]) == [ConfigSource(
            origin="synthesized: https://h:8443/y", urls_found=["https://h:8443/"])]


def _redirect(url, location, status=302):
    return ProbeResult(url=url, http_method=HttpMethod.HEAD, status_code=status,
                       www_authenticate=None, detected_method=AuthMethod.UNKNOWN,
                       location=location)


class TestRedirectSources:
    """redirect_sources turns a probe's cross-origin Location into a ConfigSource
    so the target joins the scan as a discovered URL with `redirect:` provenance.
    Cross-origin is judged by Origin, the report's service identity."""

    def test_absolute_cross_origin_target_becomes_a_source(self):
        probe = _redirect("https://api.corp/x", "https://sso.corp/adfs/ls?wa=wsignin1.0")
        assert redirect_sources([probe]) == [ConfigSource(
            origin="redirect: https://api.corp/x",
            urls_found=["https://sso.corp/adfs/ls?wa=wsignin1.0"],
        )]

    def test_relative_location_is_same_origin(self):
        # "/login" resolves against the probed URL and names its own service.
        assert redirect_sources([_redirect("https://api.corp/x", "/login")]) == []

    def test_absolute_same_origin_target_is_dropped(self):
        assert redirect_sources(
            [_redirect("https://api.corp/x", "https://api.corp/login")]) == []

    def test_scheme_change_on_one_host_is_cross_origin(self):
        # https://h is a distinct service from http://h in the report, and it is
        # where the client lands; the http origin's 301 hides its verdict.
        assert redirect_sources(
            [_redirect("http://api.corp/x", "https://api.corp/x", status=301)]
        ) == [ConfigSource(origin="redirect: http://api.corp/x",
                           urls_found=["https://api.corp/x"])]

    def test_default_port_is_the_same_origin(self):
        assert redirect_sources(
            [_redirect("https://api.corp/x", "https://api.corp:443/y")]) == []

    def test_host_comparison_is_case_insensitive(self):
        assert redirect_sources(
            [_redirect("https://api.corp/x", "HTTPS://API.CORP/y")]) == []

    def test_non_http_scheme_is_dropped(self):
        # urljoin hands back `myapp://open` verbatim; Origin.from_url is None for
        # a non-HTTP scheme, which is what keeps it out — the dependency map is
        # of HTTP services.
        assert redirect_sources([_redirect("https://api.corp/x", "myapp://open")]) == []
        assert redirect_sources([_redirect("https://api.corp/x", "mailto:a@b")]) == []

    def test_only_3xx_is_read(self):
        # A 201's Location names the resource just created, not a place the
        # client goes.
        created = ProbeResult(url="https://api.corp/x", http_method=HttpMethod.HEAD,
                              status_code=201, www_authenticate=None,
                              detected_method=AuthMethod.UNAUTHENTICATED,
                              location="https://other.corp/items/1")
        assert redirect_sources([created]) == []

    def test_3xx_without_location_yields_nothing(self):
        assert redirect_sources([_redirect("https://api.corp/x", None)]) == []
        assert redirect_sources([_redirect("https://api.corp/x", "")]) == []

    def test_transport_error_yields_nothing(self):
        # status_code is None on a transport error; must not be compared.
        failed = ProbeResult(url="https://api.corp/x", http_method=HttpMethod.HEAD,
                             status_code=None, www_authenticate=None,
                             detected_method=AuthMethod.NO_RESPONSE, error="timeout")
        assert redirect_sources([failed]) == []

    def test_malformed_target_is_still_a_source(self):
        # Quarantine is build_report's job (suspect_urls, reason bad_host); the
        # source must survive so the target is reported rather than vanishing.
        assert redirect_sources(
            [_redirect("https://api.corp/x", "http://[::1]:8080/y")]
        ) == [ConfigSource(origin="redirect: https://api.corp/x",
                           urls_found=["http://[::1]:8080/y"])]

    def test_sources_follow_probe_order(self):
        probes = [
            _redirect("https://b.corp/x", "https://sso.corp/b"),
            _redirect("https://a.corp/x", "/same-origin"),
            _redirect("https://a.corp/y", "https://sso.corp/a"),
        ]
        assert [s.origin for s in redirect_sources(probes)] == [
            "redirect: https://b.corp/x", "redirect: https://a.corp/y"]


@pytest.mark.asyncio
async def test_report_carries_probe_evidence(auth_server):
    """Probe evidence reaches the report under each service's `urls`."""
    sources = await crawl(auth_server, timeout=10000, wait_after_load=2000)
    all_urls = list({u for s in sources for u in s.urls_found})
    probes = await probe_urls(all_urls, timeout=5.0)
    auth_map = build_auth_map(probes, [])

    # unresolved=[] is the shape the pipeline always passes: the DNS pass ran
    # and every host resolved.
    report = build_report(sources, auth_map, [], {})

    assert report.services
    probed = {ev.url: ev for svc in report.services for ev in svc.urls}
    assert probed
    for url, evidence in probed.items():
        # Every probed URL reports a verdict, and `error` says why exactly when
        # that verdict is that no response came back.
        assert evidence.detected_method is not None
        assert ((evidence.detected_method is AuthMethod.NO_RESPONSE)
                == (evidence.error is not None))


# ===========================================================================
# Part 6: Authenticated Sessions
# ===========================================================================


class TestCheckAuthSignal:
    def test_clean_returns_none(self):
        assert _check_auth_signal("https://app.example.com/",
                                  "https://app.example.com/", 200, None) is None

    def test_401_signal(self):
        msg = _check_auth_signal("https://app.example.com/",
                                 "https://app.example.com/", 401, None)
        assert msg and "401" in msg

    def test_www_authenticate_signal(self):
        msg = _check_auth_signal("https://app.example.com/",
                                 "https://app.example.com/", 200, "Bearer")
        assert msg and "Bearer" in msg

    def test_off_origin_redirect(self):
        msg = _check_auth_signal("https://app.example.com/",
                                 "https://idp.example.com/login", 200, None)
        assert msg and "idp.example.com" in msg

    def test_login_url_pattern(self):
        msg = _check_auth_signal("https://app.example.com/",
                                 "https://app.example.com/login", 200, None)


# ===========================================================================
# Part 7: DNS resolution
# ===========================================================================

# The .invalid TLD (RFC 6761) is reserved and guaranteed never to resolve.
_BAD_HOST = "doesnotexist.invalid"


@pytest.mark.asyncio
async def test_resolve_hosts_returns_empty_for_resolvable():
    failures, ip_map = await resolve_hosts(["localhost"])
    assert failures == []
    # A resolvable host is captured in ip_map with its address(es).
    assert ip_map["localhost"]
    assert all(isinstance(ip, str) for ip in ip_map["localhost"])


@pytest.mark.asyncio
async def test_resolve_hosts_reports_nxdomain():
    failures, ip_map = await resolve_hosts([_BAD_HOST])
    assert len(failures) == 1
    assert failures[0]["host"] == _BAD_HOST
    assert failures[0]["error"] == "NXDOMAIN"
    assert _BAD_HOST not in ip_map  # a failed host yields no IPs


@pytest.mark.asyncio
async def test_resolve_hosts_mixed():
    failures, ip_map = await resolve_hosts(["localhost", _BAD_HOST])
    assert {entry["host"] for entry in failures} == {_BAD_HOST}
    assert ip_map.get("localhost")  # resolved
    assert _BAD_HOST not in ip_map  # failed


@pytest.mark.asyncio
async def test_resolve_hosts_dedupes():
    failures, _ = await resolve_hosts([_BAD_HOST, _BAD_HOST, _BAD_HOST])
    assert len(failures) == 1


@pytest.mark.asyncio
async def test_probe_filtering_skips_unresolved_hosts(test_server):
    """End-to-end: URLs on unresolved hosts must be excluded from probe input
    and from the auth map (build_report lists them as dns_failed services)."""
    from urllib.parse import urlparse

    good_url = f"{test_server}/config.json"
    bad_url = f"https://{_BAD_HOST}/api"
    unique_urls = [good_url, bad_url]

    # Replicate the main() flow: resolve, filter, probe, then check auth_map.
    hosts = sorted({urlparse(u).hostname for u in unique_urls if urlparse(u).hostname})
    unresolved, _ = await resolve_hosts(hosts)
    unresolved_set = {entry["host"] for entry in unresolved}

    assert _BAD_HOST in unresolved_set
    assert "127.0.0.1" not in unresolved_set

    probeable = [u for u in unique_urls if urlparse(u).hostname not in unresolved_set]

    assert probeable == [good_url]

    probes = await probe_urls(probeable, timeout=5.0)
    auth_map = build_auth_map(probes, [])

    assert bad_url not in auth_map
    assert auth_map[good_url].probe_result is not None
    assert auth_map[good_url].probe_result.status_code == 200
