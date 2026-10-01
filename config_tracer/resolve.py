"""DNS resolution of discovered hosts via the system resolver."""

import asyncio
import socket


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------

def _classify_dns_error(exc: BaseException) -> str:
    if isinstance(exc, asyncio.TimeoutError):
        return "timeout"
    if isinstance(exc, socket.gaierror):
        if exc.errno == socket.EAI_NONAME:
            return "NXDOMAIN"
        if exc.errno == socket.EAI_AGAIN:
            return "SERVFAIL"
        return f"gaierror: {exc.strerror or exc}"
    return str(exc)


async def _resolve_single(
    host: str,
    semaphore: asyncio.Semaphore,
    timeout: float,
) -> dict:
    """Resolve one host; return {host, ips} on success or {host, error} on failure.
    `ips` is the distinct resolved addresses (IPv4 + IPv6), sorted."""
    loop = asyncio.get_running_loop()
    async with semaphore:
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, None),
                timeout=timeout,
            )
            # getaddrinfo yields (family, type, proto, canonname, sockaddr);
            # sockaddr[0] is the address string for both AF_INET and AF_INET6.
            ips = sorted({info[4][0] for info in infos})
            return {"host": host, "ips": ips}
        except Exception as e:
            return {"host": host, "error": _classify_dns_error(e)}


async def resolve_hosts(
    hosts: list[str],
    timeout: float = 3.0,
    max_concurrent: int = 20,
) -> tuple[list[dict], dict[str, list[str]]]:
    """Resolve each host via the system resolver.

    Return (failures, ip_map): `failures` is [{host, error}] for hosts that
    failed to resolve (sorted by host); `ip_map` is {host: [ip, ...]} for those
    that resolved."""
    unique_hosts = list(dict.fromkeys(hosts))
    semaphore = asyncio.Semaphore(max_concurrent)
    tasks = [_resolve_single(h, semaphore, timeout) for h in unique_hosts]
    results = await asyncio.gather(*tasks)
    failures = [r for r in results if "error" in r]
    failures.sort(key=lambda r: r["host"])
    ip_map = {r["host"]: r["ips"] for r in results if "ips" in r}
    return failures, ip_map
