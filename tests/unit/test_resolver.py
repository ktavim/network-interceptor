"""Tests for crawler.network.resolver (getaddrinfo is faked; no real DNS)."""
import socket
import time

import pytest

from crawler.network.resolver import resolve_hosts, resolve_ips


def _info(family, addr):
    sockaddr = (addr, 0) if family == socket.AF_INET else (addr, 0, 0, 0)
    return (family, socket.SOCK_STREAM, 6, "", sockaddr)


@pytest.fixture
def fake_getaddrinfo(monkeypatch):
    calls = []

    def install(answer):
        def getaddrinfo(host, *args, **kwargs):
            calls.append(host)
            return answer(host)
        monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
        return calls
    return install


class TestResolveIps:
    async def test_distinct_sorted_numerically_ipv4_first(self, fake_getaddrinfo):
        fake_getaddrinfo(lambda host: [
            _info(socket.AF_INET6, "2001:db8::1"),
            _info(socket.AF_INET, "10.0.0.10"),
            _info(socket.AF_INET, "10.0.0.2"),
            _info(socket.AF_INET, "10.0.0.2"),
        ])
        assert await resolve_ips("a.com") == ["10.0.0.2", "10.0.0.10", "2001:db8::1"]

    async def test_ip_literal_resolves_to_itself(self):
        assert await resolve_ips("127.0.0.1") == ["127.0.0.1"]

    async def test_lookup_failure_is_none(self, fake_getaddrinfo):
        def fail(host):
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        fake_getaddrinfo(fail)
        assert await resolve_ips("nope.invalid") is None

    async def test_timeout_is_none(self, fake_getaddrinfo):
        def slow(host):
            time.sleep(0.2)
            return [_info(socket.AF_INET, "10.0.0.1")]
        fake_getaddrinfo(slow)
        assert await resolve_ips("slow.com", timeout=0.01) is None


class TestResolveHosts:
    async def test_each_host_looked_up_once(self, fake_getaddrinfo):
        calls = fake_getaddrinfo(lambda host: [_info(socket.AF_INET, "10.0.0.1")])
        result = await resolve_hosts(["a.com", "b.com", "a.com"])
        assert result == {"a.com": ["10.0.0.1"], "b.com": ["10.0.0.1"]}
        assert sorted(calls) == ["a.com", "b.com"]

    async def test_failure_is_per_host(self, fake_getaddrinfo):
        def answer(host):
            if host == "bad.com":
                raise socket.gaierror(socket.EAI_NONAME, "not known")
            return [_info(socket.AF_INET, "10.0.0.1")]
        fake_getaddrinfo(answer)
        assert await resolve_hosts(["good.com", "bad.com"]) == {
            "good.com": ["10.0.0.1"], "bad.com": None,
        }
