"""Core data models: discovered config sources, auth verdicts, and probe evidence."""

from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import urlparse


@dataclass
class ConfigSource:
    origin: str
    urls_found: list[str] = field(default_factory=list)


_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class Origin:
    """The scan's service identity: one HTTP origin as the three parts an F5
    VIP is defined from.

    On an internal estate a hostname is not a service: two ports on one box,
    or http vs https, are usually distinct services with their own auth, and
    collapsing them by bare hostname would hide a gated sibling behind an open
    one. `port` is always the *effective* port — 443 for `https://h`, 80 for
    `http://h` — so `https://h` and `https://h:443` are one Origin, never two,
    and no consumer (the report, the unique constraint in the database, the
    VIP definition) has to know the defaults. `host` is lowercased.

    The three fields are the identity; `key` is a rendering of them."""
    scheme: str
    host: str
    port: int

    @classmethod
    def from_url(cls, url: str) -> "Origin | None":
        """The Origin of `url`, or None if it has no host or is not http(s):
        urljoin hands back a `myapp://open` redirect target verbatim, and a
        dependency map of HTTP services has no place for it."""
        parsed = urlparse(url)
        host = parsed.hostname
        default_port = _DEFAULT_PORTS.get(parsed.scheme)
        if not host or default_port is None:
            return None
        try:
            port = parsed.port
        except ValueError:  # out-of-range port; treat as unspecified
            port = None
        return cls(parsed.scheme, host, default_port if port is None else port)

    @property
    def key(self) -> str:
        """`scheme://host[:port]` with the default port elided — the origin as a
        URL spells it. For logs, lookups and tests; not stored anywhere."""
        if self.port == _DEFAULT_PORTS[self.scheme]:
            return f"{self.scheme}://{self.host}"
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def sort_key(self) -> tuple[str, int, str]:
        """Report and API order: one box's services together, then by port."""
        return (self.host, self.port, self.scheme)


class AuthMethod(StrEnum):
    """Closed vocabulary for an auth verdict. A StrEnum so members compare
    equal to and serialize as their lowercase string value."""
    BASIC = "basic"
    BEARER = "bearer"
    NEGOTIATE = "negotiate"
    NTLM = "ntlm"
    # An uncommon but well-formed challenge scheme (Digest, vendor schemes, ...).
    # Which one is in ProbeResult.www_authenticate.
    OTHER = "other"
    OAUTH = "oauth"
    LOGIN_REDIRECT = "login_redirect"
    UNAUTHENTICATED = "unauthenticated"
    UNKNOWN = "unknown"
    # The probe got no HTTP response at all (timeout, refused, TLS failure,
    # disconnect); which one is in ProbeResult.error. Not a verdict on the
    # endpoint but on our view of it — kept apart from UNKNOWN, where the server
    # did answer, because the fix is on the network path, not in the app.
    NO_RESPONSE = "no_response"
    # The host failed DNS (NXDOMAIN, SERVFAIL, timeout), so nothing was probed;
    # which failure is in the URL's `error`. Never a ProbeResult's verdict:
    # build_report sets it on every URL of such a host, and on its services.
    # Kept apart from NO_RESPONSE because the fix is in DNS — a record, or a
    # name only resolvable from inside — and because the service has no
    # addresses for a VIP to point at.
    DNS_FAILED = "dns_failed"


# Precedence for collapsing a service's per-URL auth verdicts into one headline
# method. Earlier wins. The sort is by *blocker risk*, not by informativeness:
# the question this report answers is "can this service go behind the F5, and if
# not, why not", so the headline is the worst thing found across the service's
# URLs. The URLs are a conjunction — exposing the service means every one of
# them has to work through the F5, so a single NTLM-only path blocks it however
# clean its siblings are. It only decides the headline when a
# service's URLs disagree; nothing about probing depends on it.
_VERDICT_PRECEDENCE: tuple[AuthMethod, ...] = (
    # --- Blockers: exposure can't proceed as-is. ---
    # Technical blocker. NTLM authenticates the TCP connection, not the request,
    # so connection reuse/multiplexing at the proxy breaks the handshake.
    AuthMethod.NTLM,
    # Policy blocker, not a technical one — BASIC proxies fine. The objection is
    # that credentials ride every request, and exposure sends them outward.
    AuthMethod.BASIC,
    # A named scheme we don't recognize (Digest, vendor schemes). Ranked as a blocker by safe default —
    # unrecognized means unsupported until someone confirms otherwise — not
    # because any specific scheme is known to fail. Epistemically this is
    # NEGOTIATE's tier; it sits above only because the safe assumption differs.
    AuthMethod.OTHER,
    # --- Needs review: may or may not block; a human has to look. ---
    # Kerberos underneath is fine to expose; NTLM underneath is a blocker, and
    # the challenge alone doesn't say which.
    AuthMethod.NEGOTIATE,
    # --- Exposable: concrete and known-good. ---
    AuthMethod.BEARER,
    AuthMethod.OAUTH,
    AuthMethod.LOGIN_REDIRECT,
    # UNKNOWN outranks UNAUTHENTICATED: if open won, one open endpoint (often the
    # host root) would mask a restricted sibling in the headline — the false
    # negative this scan exists to catch.
    AuthMethod.UNKNOWN,
    # NO_RESPONSE is UNKNOWN's tier — we don't know what the URL demands — and
    # outranks UNAUTHENTICATED for the same reason: a URL we never saw must not
    # let an open sibling headline the service as exposable. It sits below
    # UNKNOWN because within one tier a real response beats none.
    AuthMethod.NO_RESPONSE,
    # The same tier again, below NO_RESPONSE because no response still beats no
    # address. The rank never decides a real headline: DNS fails per host, so
    # every URL of a service shares it and they never disagree.
    AuthMethod.DNS_FAILED,
    AuthMethod.UNAUTHENTICATED,
)

# Which scheme we would actually use when ONE response offers several at once,
# most preferred first. Used by _parse_www_authenticate; only the five schemes a
# challenge can name appear here.
#
# The reduction runs opposite to _VERDICT_PRECEDENCE because the set means
# something else. A response's challenges are a disjunction, not a conjunction:
# RFC 9110 §11.6.1 has the client pick the strongest scheme it understands, and
# here the F5 is that client. `Bearer, Basic` is exposable on Bearer, and the
# Basic it also offers costs nothing because nothing has to use it. Taking the
# worst of an offer would report a blocker the F5 would simply decline to pick.
#
# It is NOT _VERDICT_PRECEDENCE reversed, because OTHER does not survive the
# flip. OTHER ranks high there by safe default — unrecognized means unsupported
# until someone confirms otherwise — and a safe default inverts with the
# question: conservative about the worst of a conjunction, it becomes reckless
# about the best of a disjunction, claiming we would pick the one scheme we just
# said we cannot support. So OTHER moves to the bottom, last resort; the four
# schemes whose risk is actually known keep their relative order, reversed.
_OFFER_PREFERENCE: tuple[AuthMethod, ...] = (
    AuthMethod.BEARER,
    AuthMethod.NEGOTIATE,
    AuthMethod.BASIC,
    AuthMethod.NTLM,
    AuthMethod.OTHER,
)


class HttpMethod(StrEnum):
    """The request a probe sent, spelled as on the wire. A probe sends HEAD,
    and GET in its place when the HEAD gets a 405 (probe._probe_single)."""
    HEAD = "HEAD"
    GET = "GET"


@dataclass
class ProbeResult:
    """Auth evidence from HTTP probing."""
    url: str
    # The request whose answer this is: the HEAD, or the GET sent in its place,
    # so GET alone says the HEAD got a 405. On a transport error, the request
    # that failed. It is evidence like the rest: a server can answer HEAD and
    # GET differently (a route, or an auth rule, registered for GET only), so
    # the verdict is what the URL demanded of this request, and this is the
    # request that reproduces it.
    http_method: HttpMethod
    status_code: int | None
    # The response's WWW-Authenticate challenge(s), verbatim (None when absent).
    # A response may offer several at once, as repeated header lines or as one
    # comma-separated value; RFC 9110 §5.3 makes those forms equivalent and
    # _joined_www_authenticate normalizes both to the second, so this holds all
    # of them — not just the one `detected_method` was drawn from.
    www_authenticate: str | None
    # Auth verdict, an AuthMethod (one of BASIC/BEARER/NEGOTIATE/NTLM/OTHER/
    # OAUTH/LOGIN_REDIRECT/UNAUTHENTICATED/UNKNOWN), or NO_RESPONSE on a
    # transport error (see `error`, then; `status_code` is None).
    detected_method: AuthMethod
    # The response's Location header, verbatim (None when absent). Kept raw for
    # the same reason `www_authenticate` is: the verdict is the summary, this is
    # the evidence it was read off. It carries the most precisely where the
    # verdict is most confident — OAUTH says a service federates, only the header
    # says whether it federates to login.microsoftonline.com or to an ADFS box on
    # this estate, and that is the difference between exposure being routine and
    # being a question. Often relative ("/login"); resolve against `url` for the
    # absolute target. When that target is another origin it also enters the
    # scan as a discovered URL of its own, with provenance `redirect: <url>`
    # (probe.redirect_sources), so it gets resolved, probed and reported.
    location: str | None = None
    error: str | None = None


@dataclass
class AuthInfo:
    """Auth info for a single URL, derived from HTTP probing."""
    url: str
    probe_result: ProbeResult | None = None
