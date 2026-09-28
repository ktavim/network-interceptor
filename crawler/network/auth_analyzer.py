"""Authentication detection: request headers, API keys, IdP redirects, auth challenges."""
import base64
import binascii
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse, urlsplit, urlunsplit

from ..origin import Origin, origin_of


# Mechanism signatures for classifying a "Negotiate" (SPNEGO) token by scanning
# its decoded bytes, instead of a full ASN.1 parse. NTLM messages always begin
# with the literal "NTLMSSP\0" magic (also present when NTLM rides inside a
# SPNEGO mechToken); Kerberos shows up as its mech OID in DER form.
_NTLM_SIGNATURE = b"NTLMSSP\x00"
_KERBEROS_MECH_OIDS = (
    bytes((0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02)),  # 1.2.840.113554.1.2.2  (KRB5)
    bytes((0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02)),  # 1.2.840.48018.1.2.2    (MS KRB5)
)


def _classify_negotiate_token(token: str) -> str:
    """Classify a SPNEGO/"Negotiate" token by scanning its bytes (no ASN.1 parse).

    An embedded NTLM magic means NTLM is actively being exchanged (raw or as a
    SPNEGO mechToken) and wins over a merely-offered Kerberos OID, since NTLM is
    the only mechanism that changes severity. A Kerberos mech OID -> "kerberos".
    Anything else -- including a token that isn't valid base64 -- stays in the
    "negotiate" bucket, because the scheme is still unambiguously SPNEGO.
    """
    try:
        raw = base64.b64decode(token, validate=False)
    except (binascii.Error, ValueError):
        return "negotiate"
    if _NTLM_SIGNATURE in raw:
        return "ntlm"
    if any(oid in raw for oid in _KERBEROS_MECH_OIDS):
        return "kerberos"
    return "negotiate"


def _authorization_header(headers: Dict[str, str]) -> Optional[str]:
    for k, v in headers.items():
        if k.lower() == 'authorization':
            return v
    return None


def detect_authentication(headers: Dict[str, str], url: str) -> str:
    """Detect the authentication method used in the request.

    Returns a canonical short tag aligned with the FE's AuthMethod vocabulary:
    "bearer", "basic", "ntlm", "kerberos", "negotiate" (SPNEGO whose underlying
    mechanism couldn't be resolved), "api_key", "other" (an Authorization header
    carrying a real but unnamed scheme, e.g. Digest), or "unauthenticated" (no
    auth observed).
    """
    auth_header = _authorization_header(headers)

    if auth_header:
        if auth_header.startswith('Bearer '):
            return "bearer"
        if auth_header.startswith('Basic '):
            return "basic"
        if auth_header.startswith('Negotiate '):
            token = auth_header[10:].strip()
            # Fast path: base64 of the NTLM "NTLMSSP\0" magic. Otherwise fall to
            # a byte-signature scan that also catches NTLM/Kerberos wrapped in a
            # SPNEGO blob, settling on "negotiate" when no mechanism is resolvable.
            if token.startswith('TlR'):
                return "ntlm"
            return _classify_negotiate_token(token)
        if auth_header.startswith('NTLM '):
            return "ntlm"
        if auth_header.startswith('Kerberos '):
            return "kerberos"
        # A present Authorization header with an unrecognized scheme (e.g. Digest)
        # is a real but unnamed mechanism, not an absence of signal -- classify it
        # as "other", mirroring detect_auth_challenge's "other" handling
        # of an unnamed WWW-Authenticate challenge.
        return "other"

    api_key_headers = [
        'x-api-key', 'x-auth-token', 'x-auth', 'api-key', 'apikey', 'auth-token'
    ]
    for k in headers:
        if k.lower() in api_key_headers:
            return "api_key"

    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    api_key_params = ['api_key', 'apikey', 'key', 'auth_token', 'token']
    for param in api_key_params:
        if param in query_params:
            return "api_key"

    return "unauthenticated"


# An auth-scheme is an RFC 7235 token: one or more tchar (RFC 7230 s3.2.6).
# Real scheme names are short words ("AWS4-HMAC-SHA256" is the longest in
# common use); the length cap is a fence against a credential passing as one.
_AUTH_SCHEME_RE = re.compile(r"([!#$%&'*+\-.^_`|~0-9A-Za-z]+)[ \t]")
_MAX_AUTH_SCHEME_LEN = 32


def sent_auth_scheme(headers: Dict[str, str]) -> Optional[str]:
    """The auth-scheme word of the request's Authorization header, as sent.

    Value-free by construction: only the leading scheme token is kept and
    everything after the first whitespace -- the credentials -- is dropped,
    so no per-scheme grammar is needed and none can be got wrong. Case is
    preserved: this is evidence of what the client sent ("Basic", "Digest",
    "Negotiate"), not a classification -- detect_authentication decides the
    label, and this word survives where the label can't tell (an "other"
    scheme's actual name; NTLM raw vs. wrapped in Negotiate; the scheme a
    401 rejected, which the challenge then relabels).

    None when no Authorization header was sent, and also when its value is a
    single word with nothing after it: some clients send a raw JWT or API key
    as the whole header, and that word would be the secret itself. A leading
    word that isn't a token, or is longer than any real scheme name, is
    likewise treated as a credential and dropped.
    """
    value = _authorization_header(headers)
    if not value:
        return None
    match = _AUTH_SCHEME_RE.match(value)
    if match is None:
        return None
    scheme = match.group(1)
    if len(scheme) > _MAX_AUTH_SCHEME_LEN:
        return None
    return scheme


# The WWW-Authenticate grammar (RFC 7235 s4.1, now RFC 9110 s11.6.1), as far as
# splitting a value into its challenges needs:
#
#   challenge-list = 1#challenge
#   challenge      = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
#   auth-param     = token BWS "=" BWS ( token / quoted-string )
#   token68        = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
#
# The list is comma-separated at the top level, but so are a challenge's own
# auth-params, so a top-level comma alone does not separate challenges. What
# follows it does: a "name =" head continues the current challenge's params,
# a bare token opens a new challenge. A token68 is told from a param by what
# follows it -- a list boundary, not "=" and a value -- which is also how its
# trailing "=" padding is kept from reading as a param head.
_TOKEN_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_TOKEN68_RE = re.compile(r"[0-9A-Za-z\-._~+/]+=*")
_AUTH_PARAM_HEAD_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+[ \t]*=[ \t]*")


def _skip_ows(value: str, i: int) -> int:
    n = len(value)
    while i < n and value[i] in ' \t':
        i += 1
    return i


def _at_list_boundary(value: str, i: int) -> bool:
    i = _skip_ows(value, i)
    return i >= len(value) or value[i] == ','


def _skip_quoted_string(value: str, i: int) -> int:
    """Index just past the quoted-string whose opening '"' is at value[i].

    Honours quoted-pair escapes (a backslash-escaped quote does not close the
    string). An unterminated string runs to the end of the value.
    """
    n = len(value)
    i += 1
    while i < n:
        ch = value[i]
        if ch == '\\' and i + 1 < n:
            i += 2
            continue
        i += 1
        if ch == '"':
            break
    return i


def _skip_to_list_comma(value: str, i: int) -> int:
    """Index of the first top-level comma at or after i, or len(value).

    Commas inside quoted strings are not list separators and are skipped.
    """
    n = len(value)
    while i < n:
        ch = value[i]
        if ch == ',':
            return i
        if ch == '"':
            i = _skip_quoted_string(value, i)
            continue
        i += 1
    return n


def _skip_auth_params(value: str, i: int) -> int:
    """Index just past the #auth-param list that starts at value[i].

    Returns i unchanged when no param starts there. Stops at the first
    top-level comma that is followed by something other than a "name ="
    head: that comma separates challenges, not params.
    """
    n = len(value)
    while True:
        head = _AUTH_PARAM_HEAD_RE.match(value, i)
        if head is None:
            return i
        i = head.end()
        if i < n and value[i] == '"':
            i = _skip_quoted_string(value, i)
        else:
            token = _TOKEN_RE.match(value, i)
            if token is not None:
                i = token.end()
        comma = _skip_ows(value, i)
        if comma >= n or value[comma] != ',':
            return i
        after = comma
        while after < n and value[after] in ' \t,':
            after += 1
        if _AUTH_PARAM_HEAD_RE.match(value, after) is None:
            return comma
        i = after


def _parse_challenges(value: str) -> List[Tuple[str, Optional[str]]]:
    """Split a WWW-Authenticate value into its (auth-scheme, token68) pairs.

    token68 is None for a challenge that carries auth-params or nothing. The
    auth-params themselves are not returned: the label only needs the scheme,
    and the caller keeps the raw value as evidence. Malformed input never
    raises; whatever cannot be read is dropped up to the next top-level comma,
    so one bad element does not hide the schemes around it.
    """
    challenges: List[Tuple[str, Optional[str]]] = []
    n = len(value)
    i = 0
    while True:
        # Skip OWS and empty list elements ("Basic,, Bearer" is legal).
        while i < n and value[i] in ' \t,':
            i += 1
        if i >= n:
            return challenges
        scheme_match = _TOKEN_RE.match(value, i)
        if scheme_match is None:
            # Not a token where an auth-scheme must be: drop the element.
            i = _skip_to_list_comma(value, i)
            continue
        scheme = scheme_match.group(0)
        i = scheme_match.end()
        token68 = None
        j = _skip_ows(value, i)
        if j < n and value[j] != ',':
            t68 = _TOKEN68_RE.match(value, j)
            if t68 is not None and _at_list_boundary(value, t68.end()):
                token68 = t68.group(0)
                i = t68.end()
            else:
                i = _skip_auth_params(value, j)
        challenges.append((scheme, token68))
        # Anything the element still holds is malformed: drop it.
        i = _skip_to_list_comma(value, i)


def _challenge_tag(scheme: str, token68: Optional[str]) -> str:
    """Tag one parsed challenge with detect_authentication's vocabulary.

    The scheme is matched as a whole token, so "Basically" is "other", not
    Basic. A Negotiate challenge carrying a token68 is a handshake in flight
    (the server's SPNEGO/NTLM continuation on a 401), and that token names the
    mechanism actually being exchanged: it is resolved the same way as the
    request side's Negotiate credential, so a mid-handshake 401 cannot relabel
    an NTLM exchange as mere "negotiate".
    """
    lower = scheme.lower()
    if lower == 'basic':
        return "basic"
    if lower == 'bearer':
        return "bearer"
    if lower == 'ntlm':
        return "ntlm"
    if lower == 'negotiate':
        return _classify_negotiate_token(token68) if token68 else "negotiate"
    if lower == 'kerberos':
        return "kerberos"
    return "other"


def detect_auth_challenge(challenge: str) -> str:
    """Resolve a WWW-Authenticate value to the most favorable scheme it offers.

    The value may hold several challenges: RFC 7235 lets a server list them
    comma-separated, and Playwright's response.headers joins repeated
    WWW-Authenticate headers into one such list, so two headers and one
    multi-challenge header arrive here in the same shape. Every challenge is
    parsed (_parse_challenges) and tagged (_challenge_tag), and the tag that
    ranks lowest in _AUTH_RANK wins: the server accepts any one of the
    schemes it lists, so whoever fronts the endpoint can pick the most
    favorable one. "Bearer, Basic" is publishable with Bearer, and
    "Negotiate, NTLM" (IIS Windows Authentication's default) is publishable
    through Negotiate; neither is a blocker for also accepting the weaker
    scheme. "Negotiate, Digest" resolves to negotiate too: a known path wins
    over a scheme the tool cannot vouch for. This is the opposite direction
    from aggregate_by_origin, where every URL must work and the least
    favorable one decides. Ties keep the server's order. The schemes not
    chosen stay visible in the raw challenge the caller keeps as evidence.

    Only the scheme (and a Negotiate token68) is examined; parameters such as
    realm are left to the caller to retain as evidence. An unnamed scheme
    (e.g. Digest) is "other" -- a real but unnamed mechanism, not an absence
    of signal -- as is a value in which no scheme can be read at all.
    """
    tags = [_challenge_tag(scheme, token68) for scheme, token68 in _parse_challenges(challenge or "")]
    if not tags:
        return "other"
    return min(tags, key=_auth_rank)


# Host substrings that identify a third-party Identity Provider. Matching is by
# substring so tenant subdomains (dev-123.okta.com, mypool.amazoncognito.com) and
# regional hosts (cognito-idp.us-east-1.amazonaws.com) are all covered.
_IDP_DOMAINS = (
    'auth0.com',
    'okta.com',
    'oktapreview.com',
    'login.microsoftonline.com',
    'accounts.google.com',
    'cognito-idp',
    'amazoncognito.com',
    'onelogin.com',
    'pingidentity.com',
)


def detect_idp_redirect(location: str) -> Optional[str]:
    """Detect if a Location URL points to an Identity Provider.

    Returns the matched host as raw evidence:
    the host preserves the tenant (which Okta org, which Cognito pool). Callers treat
    any non-None result as "this redirect is an IdP handoff" -- that boolean, not
    the string, is what drives classification.

    Two shapes are returned, so the weaker match stays distinguishable:
    - a known IdP host  -> the host alone ("myapp.auth0.com"), asserting the host
      *is* an IdP;
    - an OAuth/OIDC-shaped path on any other host -> "host/path"
      ("mysite.com/oauth/authorize"), asserting only that the endpoint looks like
      an authorization endpoint -- it is often the app's own. Carrying the path
      also keeps the result non-empty for a relative Location ("/oauth/authorize"),
      which has no netloc at all.

    The query string is always dropped: it carries state/nonce/redirect_uri and,
    on some providers, user identifiers that don't belong in a stored record.
    """
    try:
        parsed = urlparse(location)
        domain = parsed.netloc.lower()

        if any(idp in domain for idp in _IDP_DOMAINS):
            return domain

        if '/oauth' in parsed.path or '/oidc' in parsed.path:
            return f"{domain}{parsed.path}"

        return None
    except Exception:
        return None


def strip_url(url: str) -> str:
    """A request URL minus query, fragment and userinfo.

    Applied by the interceptor as it records a request, so nothing
    secret-bearing survives: query values carry API keys and tokens, userinfo
    carries credentials, and a fragment is never sent to the server.
    """
    parts = urlsplit(url)
    netloc = parts.netloc.rsplit('@', 1)[-1]
    return urlunsplit((parts.scheme, netloc, parts.path, '', ''))


# Ranking shared by the two aggregations, which read it in opposite directions.
# Ordered by distance from a clean publish, in step with the tiers of
# api.translate.severity_for: the blockers rank highest -- Basic and NTLM, then
# "other", a scheme the tool cannot name and so one the publish does not
# support -- the review tier sits below them (negotiate, a known scheme whose
# mechanism went unresolved, then the "unknown" fallback), and "no auth
# observed" ranks lowest of the answers. Below it is "no_response", a request
# that sent no credentials and got no answer at all: review-tier, but any
# answer from the origin outranks it, so it labels an origin only when nothing
# on it answered. aggregate_by_origin takes the maximum over an
# origin's requests: every URL must be publishable, so an origin is as hard as
# its hardest URL, and a URL that only takes an unsupported scheme is never
# masked by an accepted credential elsewhere on the origin.
# detect_auth_challenge takes the minimum over one response's challenges: the
# server accepts any one of them, so an endpoint is as easy as its most
# favorable offer.
_AUTH_RANK = {
    "basic": 8,
    "ntlm": 8,
    "other": 7,
    "negotiate": 6,
    "unknown": 5,
    "kerberos": 4,
    "bearer": 3,
    "oauth": 2,
    "api_key": 1,
    "unauthenticated": 0,
    "no_response": -1,
}


def _auth_rank(value: str) -> int:
    """Rank an authentication tag by its scheme for origin aggregation.

    The crawler's tags are a closed set -- a detect_authentication tag, the scheme
    tag a 401 challenge resolved to, an "oauth" IdP redirect, or "no_response" for
    a failed request that sent no credentials -- and they are the
    keys of _AUTH_RANK, so the table is the whole classification and matching is
    exact. Those keys are also the tags translate.tag_to_auth_method maps to
    AuthMethod, so an origin's rank agrees with the scheme the FE will ultimately show.
    A scheme the server demanded therefore counts the same as one actually
    observed. Both an unnamed 401 challenge and an Authorization header carrying an
    unnamed scheme surface as "other": a blocker like Basic and NTLM, since only
    the named schemes are supported for the publish, ranked just below those two.
    Read upward for an origin, that puts the URL with the scheme nobody can name
    forward as the label and evidence row -- its raw challenge or sent scheme is
    where the reviewer learns what it is -- instead of letting the common
    Negotiate case swallow it, while a named blocker on another URL still wins
    as the more informative label. Read downward within one response
    (detect_auth_challenge), it loses to negotiate and to every named
    publishable scheme, so a known path is preferred over one the tool cannot
    vouch for and an endpoint is not blocked for also offering an unnamed
    scheme. Below negotiate comes the "unknown" fallback (reached only by a tag
    outside the set), and every named scheme outranks unauthenticated, which
    outranks no_response: an answer without credentials is still an answer.
    """
    return _AUTH_RANK.get((value or "").strip().lower(), _AUTH_RANK["unknown"])


def aggregate_by_origin(requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group requests by origin and pick the most specific authentication seen.

    The key is the (scheme, host, port) triple rather than the hostname: each
    origin is a separate listener to publish, and "http://x" and "https://x" (or
    "x:8443") can be different services with different authentication. Requests
    whose URL has no origin are skipped.

    Each entry carries `urls`: a copy of every request record folded into it,
    in capture order. These become the service's `urls` rows;
    core.translate.url_to_row picks the columns. The records are already
    redacted at capture (see NetworkInterceptor).

    `evidence_index` is the position in `urls` of the request whose
    authentication classification "wins" (the first one seen at the winning
    rank). That row is the service's evidence: the FE presents its status, page,
    challenge and IdP redirect, so no separate evidence sample is kept here.
    """
    result_map: Dict[Origin, Dict[str, Any]] = {}
    for req in requests:
        origin = origin_of(req['url'])
        if origin is None:
            continue

        record = dict(req)
        current_auth = req.get('authentication', 'unauthenticated')

        if origin not in result_map:
            result_map[origin] = {
                'scheme': origin.scheme,
                'host': origin.host,
                'port': origin.port,
                'authentication': current_auth,
                'urls': [record],
                'evidence_index': 0,
            }
            continue

        entry = result_map[origin]
        entry['urls'].append(record)

        existing_auth = entry['authentication']
        # Rank by scheme (_auth_rank): the most notable auth seen on any of the
        # origin's requests wins as its label. A strictly higher rank also makes
        # this request the evidence; equal ranks keep the first request seen.
        # The index is taken from `urls`, not the loop, since origin-less
        # requests are skipped above and never occupy a position.
        if _auth_rank(current_auth) > _auth_rank(existing_auth):
            entry['authentication'] = current_auth
            entry['evidence_index'] = len(entry['urls']) - 1

    return list(result_map.values())
