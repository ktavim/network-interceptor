"""Anonymous HTTP probing of discovered URLs to classify their auth scheme."""

import asyncio
import re
import ssl
from collections.abc import Iterable
from urllib.parse import urljoin, urlparse

import aiohttp

from .models import (
    AuthInfo, AuthMethod, ConfigSource, HttpMethod, Origin, ProbeResult, _OFFER_PREFERENCE,
)


# ---------------------------------------------------------------------------
# HTTP probing
# ---------------------------------------------------------------------------

# RFC 9110 tchar — the characters legal in a scheme name or an auth-param name.
_TCHAR = r"!#$%&'*+\-.^_`|~0-9A-Za-z"
# A comma-piece shaped `token=` is an auth-param continuing the challenge before
# it, not a new challenge. BWS around the `=` is legal, hence the \s*.
_AUTH_PARAM_RE = re.compile(rf"^[{_TCHAR}]+\s*=")

_KNOWN_SCHEMES = {"basic", "bearer", "negotiate", "ntlm"}


def _split_unquoted_commas(value: str) -> list[str]:
    """Split on the commas that sit outside a quoted-string.

    An auth-param value may contain a comma of its own (realm="a,b"), which a
    plain str.split(",") would tear in half."""
    pieces: list[str] = []
    current: list[str] = []
    in_quotes = False
    escaped = False
    for ch in value:
        if escaped:
            escaped = False
        elif ch == "\\" and in_quotes:
            escaped = True
        elif ch == '"':
            in_quotes = not in_quotes
        elif ch == "," and not in_quotes:
            pieces.append("".join(current))
            current = []
            continue
        current.append(ch)
    pieces.append("".join(current))
    return pieces


def _challenge_schemes(header: str) -> list[str]:
    """Return the lowercased scheme name of every challenge in a header value.

    One value can carry several challenges — and the auth-params *inside* a
    single challenge are comma-separated too, so the pieces have to be told
    apart rather than merely split: `Digest realm="x", qop="auth"` is one
    challenge, `Negotiate, NTLM` is two. A piece shaped `token=` is a param;
    anything else opens a challenge whose first token names the scheme."""
    schemes: list[str] = []
    for piece in _split_unquoted_commas(header):
        piece = piece.strip()
        if not piece or _AUTH_PARAM_RE.match(piece):
            continue
        schemes.append(piece.split()[0].lower())
    return schemes


def _parse_www_authenticate(header: str) -> AuthMethod:
    """Reduce a WWW-Authenticate header value to one AuthMethod verdict.

    A known challenge scheme maps to its AuthMethod, an unrecognized but
    well-formed one to OTHER, and a header that names no scheme at all — empty,
    whitespace, or nothing but auth-params — to UNKNOWN.

    A server may offer several schemes at once — on this estate usually IIS's
    `Negotiate` ahead of `NTLM`. The offer is the client's to choose from, so
    the verdict is the scheme we would pick, the best on offer by
    _OFFER_PREFERENCE. Note this is the opposite reduction to the one
    _collapse_host_verdict runs over a service's URLs, because a service's URLs
    all have to work and a response's challenges only need one to.

    Convention puts the strongest scheme first, so reading the leading token
    would usually land in the same place — but on the server's ordering, not on
    ours, and the whole offer is on ProbeResult.www_authenticate either way for
    anyone who needs to see what else was accepted."""
    offered = {
        AuthMethod(s) if s in _KNOWN_SCHEMES else AuthMethod.OTHER
        for s in _challenge_schemes(header)
    }
    for method in _OFFER_PREFERENCE:
        if method in offered:
            return method
    return AuthMethod.UNKNOWN


def _host_root_url(url: str) -> str | None:
    """Return scheme://host[:port]/ if the URL has a path beyond /, else None."""
    parsed = urlparse(url)
    if parsed.path and parsed.path.rstrip("/"):
        root = f"{parsed.scheme}://{parsed.netloc}/"
        return root
    return None


def _joined_www_authenticate(resp: aiohttp.ClientResponse) -> str | None:
    """Return every WWW-Authenticate line of a response, joined into one value,
    or None if it sent none.

    A server offering several schemes may repeat the header instead of
    comma-separating one value — IIS sends `Negotiate` and `NTLM` on their own
    lines. aiohttp keeps repeats as separate multidict entries and .get() hands
    back only the first, which would drop the rest from the verdict *and* from
    the evidence field that exists to be read by a human. RFC 9110 §5.3 makes
    the comma-joined form equivalent, so joining loses nothing and leaves
    _parse_www_authenticate one shape to read instead of two."""
    values = resp.headers.getall("WWW-Authenticate", ())
    return ", ".join(values) if values else None


async def _send(
    session: aiohttp.ClientSession,
    method: HttpMethod,
    url: str,
    timeout: float,
) -> tuple[int, str | None, str]:
    """Send one request. Return (status_code, www_authenticate, location)."""
    async with session.request(method, url, timeout=aiohttp.ClientTimeout(total=timeout),
                               allow_redirects=False) as resp:
        return (resp.status,
                _joined_www_authenticate(resp),
                resp.headers.get("Location", ""))


def _classify_redirect(location: str, url: str) -> AuthMethod:
    """Sub-classify a 3xx response into a detected_method.

    An auth-flagged redirect is a real auth verdict (OAUTH / LOGIN_REDIRECT); a
    plain route change is not a method, so it is UNKNOWN.
    ProbeResult.location keeps the target verbatim."""
    if not location:
        return AuthMethod.UNKNOWN
    has_keyword = any(kw in location.lower()
                      for kw in ("oauth", "authorize", "login", "auth"))
    # Compare the redirect target's host to the probed host. A federated
    # SSO/OAuth flow points off-host (login.microsoftonline.com, an ADFS
    # box, sso.corp.local); a local form-login points back at the same
    # origin. Resolve first — servers commonly send a relative Location
    # like "/login", whose hostname is empty until joined with the URL.
    target = urljoin(url, location)
    target_host = (urlparse(target).hostname or "").lower()
    probed_host = (urlparse(url).hostname or "").lower()
    off_host = bool(target_host) and target_host != probed_host
    if has_keyword:
        return AuthMethod.OAUTH if off_host else AuthMethod.LOGIN_REDIRECT
    return AuthMethod.UNKNOWN


def _classify_probe(status: int, www_auth: str | None, location: str = "",
                    url: str = "") -> AuthMethod:
    """Classify a probe response into an AuthMethod verdict."""
    # A WWW-Authenticate challenge is authoritative on any status, not just
    # 401. RFC 6750 (OAuth Bearer) returns it on 403 for insufficient_scope,
    # and the header MAY appear on other statuses per RFC 7235 §4.1.
    if www_auth:
        return _parse_www_authenticate(www_auth)
    if 200 <= status < 300:
        return AuthMethod.UNAUTHENTICATED
    if 300 <= status < 400:
        return _classify_redirect(location, url)
    # Everything else — 401, the coarse 4xx (400/403/404/407), 5xx, and any
    # status outside those ranges — tells us nothing about auth.
    return AuthMethod.UNKNOWN


def _classify_probe_error(exc: BaseException) -> str:
    """Render a transport error from probing as a short, non-empty reason.

    Mirrors _classify_dns_error. aiohttp's `total` timeout raises a bare
    asyncio.TimeoutError whose str() is the empty string, so a plain str(exc)
    would leave ProbeResult.error uninformative (""). Bucket the common cases
    and always fall back to a non-empty representation."""
    if isinstance(exc, asyncio.TimeoutError):
        # Also catches aiohttp.ServerTimeoutError (a subclass); the headline is
        # "timeout" regardless of which clock (total/connect/read) fired.
        return "timeout"
    if isinstance(exc, ssl.SSLError):
        reason = getattr(exc, "reason", None)
        return f"TLS error: {reason}" if reason else "TLS error"
    if isinstance(exc, aiohttp.ClientConnectorError):
        # The wrapped OSError carries the actionable detail (connection
        # refused, no route to host, ...).
        os_err = getattr(exc, "os_error", None)
        if os_err is not None:
            return f"connection failed: {os_err.strerror or os_err}"
        return f"connection failed: {exc}"
    if isinstance(exc, aiohttp.ServerDisconnectedError):
        return "server disconnected"
    if isinstance(exc, aiohttp.ClientConnectionError):
        return f"connection error: {exc}".rstrip(": ")
    return str(exc) or repr(exc)


async def _probe_single(
    session: aiohttp.ClientSession,
    url: str,
    semaphore: asyncio.Semaphore,
    timeout: float,
) -> ProbeResult:
    """Probe a single URL for auth requirements. Returns the path's own verdict;
    host-root enrichment is handled separately by probe_urls_with_roots.

    A HEAD, and a GET in its place when the HEAD gets a 405. The result is the
    last request's, and `http_method` names that request, including when it
    failed at the transport."""
    async with semaphore:
        method = HttpMethod.HEAD
        try:
            status, www_auth, location = await _send(session, method, url, timeout)
            if status == 405:
                method = HttpMethod.GET
                status, www_auth, location = await _send(session, method, url, timeout)
            return ProbeResult(
                url=url,
                http_method=method,
                status_code=status,
                www_authenticate=www_auth,
                detected_method=_classify_probe(status, www_auth, location, url),
                location=location or None,
            )
        except Exception as e:
            return ProbeResult(
                url=url,
                http_method=method,
                status_code=None,
                www_authenticate=None,
                detected_method=AuthMethod.NO_RESPONSE,
                error=_classify_probe_error(e),
            )


def _probe_ssl_context() -> ssl.SSLContext:
    """Build the TLS context used for probing, deliberately WITHOUT ALPN.

    aiohttp's default context calls set_alpn_protocols(("http/1.1",)), which
    advertises "I explicitly decline HTTP/2" in the ClientHello. Every real
    browser offers ("h2", "http/1.1"), so http/1.1-only reads as a bot
    fingerprint and CDN/WAF tiers reject the handshake's request outright --
    Fastly answers 403 with an empty body, `Retry-After: 0` and a
    single `Via`, i.e. an edge synthetic that never reached the origin. That
    403 is indistinguishable from a real "this path is gated" and silently
    poisons the auth verdict, which matters most on the internal estate this
    tool is pointed at: F5 ASM fingerprints clients the same way.

    Offering no ALPN at all sidesteps the rule -- servers then fall back to
    HTTP/1.1, which is the only protocol aiohttp speaks. Do NOT offer "h2"
    here: the server would negotiate HTTP/2 and aiohttp would write HTTP/1.1
    bytes into an h2 connection."""
    return ssl.create_default_context()


async def probe_urls(
    urls: list[str],
    timeout: float = 5.0,
    max_concurrent: int = 10,
) -> list[ProbeResult]:
    """Probe a list of URLs for authentication requirements.

    The probe is deliberately anonymous. Sending a session would invert the answer. 
    The probe classifies what anendpoint *demands*, so an authenticated request 
    turns a gated URL into a 200 and the verdict into UNAUTHENTICATED — backwards 
    exactly where it costs most, since "open" is the finding that decides whether 
    the F5 may expose it."""
    unique_urls = list(dict.fromkeys(urls))  # deduplicate, preserve order
    semaphore = asyncio.Semaphore(max_concurrent)
    async with aiohttp.ClientSession(
        headers={"User-Agent": "ConfigTracer/1.0"},
        connector=aiohttp.TCPConnector(ssl=_probe_ssl_context()),
    ) as session:
        tasks = [_probe_single(session, url, semaphore, timeout) for url in unique_urls]
        return await asyncio.gather(*tasks)


def _triggers_root(p: ProbeResult) -> bool:
    """True for a path we couldn't read: gated or rejected (400/401/403) without
    naming a scheme, the case a probe of its host root may still disclose."""
    return p.status_code in (400, 401, 403) and p.detected_method is AuthMethod.UNKNOWN


async def probe_urls_with_roots(
    urls: list[str],
    *,
    timeout: float = 5.0,
    max_concurrent: int = 10,
) -> tuple[list[ProbeResult], list[ProbeResult]]:
    """Probe `urls`, then for any host with a path we couldn't read (400/401/403,
    scheme not named) probe that host's root once to try to disclose the scheme.

    The probe fires on 401/403 ("this path is gated, scheme undisclosed") and on
    400 ("rejected before auth could be evaluated" — WAF, wrong verb/content-type,
    SNI). Those mean different things about the path, but neither is read back
    onto it: the root's verdict is reported as the root's own entry and nothing
    else, leaving what it implies about a sibling path to the reader.

    Returns (path_probes, root_probes). root_probes are for synthesized
    host-root URLs not already in `urls`, filtered to those that disclosed
    something useful (a concrete scheme, or UNAUTHENTICATED = 'front door
    open'); UNKNOWN or NO_RESPONSE roots add nothing and are dropped. The path keeps its own
    verdict — the root is never substituted into it. synthesized_sources names
    the paths behind each root."""
    kw = dict(timeout=timeout, max_concurrent=max_concurrent)
    path_probes = await probe_urls(urls, **kw)

    probed = set(urls)
    roots: list[str] = []
    seen: set[str] = set()
    for p in path_probes:
        if _triggers_root(p):
            root = _host_root_url(p.url)
            if root and root not in probed and root not in seen:
                seen.add(root)
                roots.append(root)

    root_probes: list[ProbeResult] = []
    if roots:
        raw = await probe_urls(roots, **kw)
        root_probes = [r for r in raw
                       if r.detected_method not in (AuthMethod.UNKNOWN,
                                                    AuthMethod.NO_RESPONSE)]
    return path_probes, root_probes


def build_auth_map(path_probes: list[ProbeResult],
                   root_probes: list[ProbeResult]) -> dict[str, AuthInfo]:
    """Build url -> AuthInfo map.

    The path probes alone account for every probeable URL: probe_urls returns
    exactly one result per URL it was given, a transport failure included (that
    comes back as a NO_RESPONSE ProbeResult carrying `error`, never as a missing
    entry).

    Host roots we probed on our own initiative are added as entries of their
    own; synthesized_sources gives them their provenance. A root that was also
    probed as a path keeps that URL's own probe, since setdefault never replaces
    one. Within one probe_urls_with_roots call that cannot happen — it never
    re-probes a URL it was handed — but across the pipeline's hops a root one
    hop synthesized can be another hop's config URL or redirect target."""
    auth_map = {p.url: AuthInfo(url=p.url, probe_result=p) for p in path_probes}
    for probe in root_probes:
        auth_map.setdefault(probe.url, AuthInfo(url=probe.url, probe_result=probe))
    return auth_map


def synthesized_sources(path_probes: Iterable[ProbeResult],
                        root_probes: Iterable[ProbeResult]) -> list[ConfigSource]:
    """Turn the host roots among `root_probes` into ConfigSources — one per path
    probe whose undisclosed 400/401/403 set a root off, in input order — so each
    root carries the provenance `synthesized: <that path>`.

    `path_probes` and `root_probes` are the pair one probe_urls_with_roots call
    returned. It probes the root of every path that triggers one, unless it was
    handed that root itself, so each triggering path of a root among
    `root_probes` is one it was probed for. A root that call dropped (UNKNOWN,
    NO_RESPONSE) is not among them and gets no source: naming it would list it
    in the report with nothing probed.

    Riding ConfigSource, as redirect_sources does, keeps a root's provenance in
    `sources` beside every other URL's: a root no config referenced has only
    `synthesized:` sources, so the report never implies the app named `/`, and
    it still says which paths sent the scanner there."""
    roots = {r.url for r in root_probes}
    found: list[ConfigSource] = []
    for p in path_probes:
        root = _host_root_url(p.url) if _triggers_root(p) else None
        if root is not None and root in roots:
            found.append(ConfigSource(origin=f"synthesized: {p.url}", urls_found=[root]))
    return found


def redirect_sources(probes: Iterable[ProbeResult]) -> list[ConfigSource]:
    """Turn the cross-origin redirects among `probes` into ConfigSources — one per
    redirecting probe, in input order — so their targets join the scan as
    discovered URLs with the provenance `redirect: <the URL that redirected>`.

    A Location header is the one place a dependency can appear that no config
    ever spelled out. The client follows it, so exposing the redirecting service
    means exposing the target too, and the target has an auth front door of its
    own that only a probe of its own can classify. Until it is named as a
    ConfigSource it is nothing but a string on ProbeResult.location.

    Cross-ORIGIN, by Origin, not cross-host: the report's service identity is
    the origin, so http://h/x -> https://h/x names a second service — and the
    one the client actually lands on, whose verdict the http origin's 301 hides.
    _classify_redirect compares hostnames because it answers a different question
    (federated to another box, or a local form login), so http://h/x ->
    https://h/login is both a LOGIN_REDIRECT verdict and a dependency. A
    same-origin redirect ("/login") names a service already in the report and is
    dropped.

    Only 3xx responses are read: a Location on a 201 names the resource just
    created, not a place the client goes. Only http(s) targets are kept: urljoin
    hands back `myapp://open` verbatim, and Origin.from_url is None for it, so
    it never keys a service. Nothing else is filtered here. A malformed
    target still becomes a source, so build_report quarantines it under
    suspect_urls with this provenance rather than it vanishing; deciding what to
    probe is the pipeline's job.

    Riding ConfigSource rather than a flag means the report, the database and the
    API need no change, and a target on a host that fails DNS is reported as a
    dns_failed service with its provenance for free. The target's verdict is never
    read back onto the redirecting URL, which keeps its own — the rule the root
    probe already follows.

    Known gap: probe_urls_with_roots drops synthesized roots whose verdict is
    UNKNOWN, so a root probed on our own initiative that answers a plain,
    no-keyword cross-origin 3xx never reaches here. The app never referenced
    that root, so its redirect is not the app's dependency; the filter stays."""
    found: list[ConfigSource] = []
    for p in probes:
        if p.status_code is None or not 300 <= p.status_code < 400 or not p.location:
            continue
        target = urljoin(p.url, p.location)
        origin = Origin.from_url(target)
        if origin is None or origin == Origin.from_url(p.url):
            continue
        found.append(ConfigSource(origin=f"redirect: {p.url}", urls_found=[target]))
    return found
