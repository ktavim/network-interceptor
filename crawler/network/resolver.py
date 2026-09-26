"""Resolve origin hosts to the IP addresses an F5 pool's members point at."""
import asyncio
import ipaddress
import logging
import socket
from typing import Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

RESOLVE_TIMEOUT_S = 5.0


async def resolve_ips(host: str, timeout: float = RESOLVE_TIMEOUT_S) -> Optional[List[str]]:
    """Every address `host` resolves to, IPv4 before IPv6, or None when the lookup fails."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout
        )
    except (OSError, asyncio.TimeoutError) as e:
        logger.warning("Could not resolve %s: %s", host, e)
        return None
    addrs = {ipaddress.ip_address(info[4][0]) for info in infos}
    return [str(a) for a in sorted(addrs, key=lambda a: (a.version, a))]


async def resolve_hosts(hosts: Iterable[str]) -> Dict[str, Optional[List[str]]]:
    """resolve_ips for each distinct host, concurrently."""
    unique = sorted(set(hosts))
    results = await asyncio.gather(*(resolve_ips(h) for h in unique))
    return dict(zip(unique, results))
