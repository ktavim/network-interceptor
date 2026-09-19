"""URL origin: the (scheme, host, port) triple that identifies one network listener."""
from typing import NamedTuple, Optional
from urllib.parse import urlparse


_DEFAULT_PORTS = {"http": 80, "https": 443}


class Origin(NamedTuple):
    """One listener, as the F5 side will have to publish it.

    `port` is always the effective port -- the scheme's default when the URL names
    none -- so "https://x" and "https://x:443" are the same origin, and the triple
    never carries a None that would break equality or a SQL unique constraint.
    `host` is the bare hostname: lowercased, without userinfo or port, and with an
    IPv6 literal unbracketed.
    """

    scheme: str
    host: str
    port: int

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        if _DEFAULT_PORTS.get(self.scheme) == self.port:
            return f"{self.scheme}://{host}"
        return f"{self.scheme}://{host}:{self.port}"


def origin_of(url: str) -> Optional[Origin]:
    """Resolve a URL to its Origin, or None when it doesn't address a listener.

    None covers a URL with no hostname (relative, "data:", "blob:", garbage), a
    malformed port, and a port-less URL whose scheme has no known default.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if not host:
        return None
    scheme = parsed.scheme.lower()
    if port is None:
        port = _DEFAULT_PORTS.get(scheme)
    if port is None:
        return None
    return Origin(scheme, host, port)
