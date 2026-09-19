"""Tests for crawler.origin."""
import pytest

from crawler.origin import Origin, origin_of


class TestOriginOf:
    def test_http_default_port(self):
        assert origin_of("http://example.com/x") == Origin("http", "example.com", 80)

    def test_https_default_port(self):
        assert origin_of("https://example.com/x") == Origin("https", "example.com", 443)

    def test_explicit_default_port_is_same_origin(self):
        assert origin_of("https://example.com:443/x") == origin_of("https://example.com/y")
        assert origin_of("http://example.com:80/x") == origin_of("http://example.com/y")

    def test_explicit_port(self):
        assert origin_of("https://example.com:8443/x") == Origin("https", "example.com", 8443)

    def test_scheme_separates_origins(self):
        assert origin_of("http://example.com/") != origin_of("https://example.com/")

    def test_port_separates_origins(self):
        assert origin_of("https://example.com/") != origin_of("https://example.com:8443/")

    def test_scheme_and_host_are_case_folded(self):
        assert origin_of("HTTPS://Example.COM/x") == Origin("https", "example.com", 443)

    def test_userinfo_is_dropped(self):
        # Credentials embedded in a URL must never reach the stored host.
        assert origin_of("https://user:secret@example.com/x") == Origin("https", "example.com", 443)

    def test_path_query_fragment_ignored(self):
        assert origin_of("https://example.com/a/b?q=1#frag") == origin_of("https://example.com")

    def test_ipv6_host_is_unbracketed(self):
        assert origin_of("http://[::1]:8080/x") == Origin("http", "::1", 8080)

    @pytest.mark.parametrize(
        "url",
        [
            "",
            "not a url",
            "/relative/path",
            "data:text/plain;base64,QQ==",
            "blob:https://example.com/uuid",
            "javascript:void(0)",
            "mailto:someone@example.com",
        ],
    )
    def test_no_hostname_is_none(self, url):
        assert origin_of(url) is None

    def test_malformed_port_is_none(self):
        assert origin_of("http://example.com:notaport/x") is None
        assert origin_of("http://example.com:99999/x") is None

    def test_unknown_scheme_without_port_is_none(self):
        # No default port to fall back on, so it doesn't address a known listener.
        assert origin_of("ftp://example.com/file") is None

    def test_unknown_scheme_with_explicit_port(self):
        assert origin_of("ftp://example.com:2121/file") == Origin("ftp", "example.com", 2121)


class TestOriginStr:
    def test_default_port_is_elided(self):
        assert str(Origin("https", "example.com", 443)) == "https://example.com"
        assert str(Origin("http", "example.com", 80)) == "http://example.com"

    def test_non_default_port_is_shown(self):
        assert str(Origin("https", "example.com", 8443)) == "https://example.com:8443"
        # 443 is only the default for https.
        assert str(Origin("http", "example.com", 443)) == "http://example.com:443"

    def test_ipv6_is_rebracketed(self):
        assert str(Origin("http", "::1", 8080)) == "http://[::1]:8080"
