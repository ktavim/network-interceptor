"""Authentication detection: request headers, API keys, IdP redirects, auth challenges."""
import base64
import binascii
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

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


def detect_authentication(headers: Dict[str, str], url: str) -> str:
    """Detect the authentication method used in the request.

    Returns a canonical short tag aligned with the FE's AuthMethod vocabulary:
    "bearer", "basic", "ntlm", "kerberos", "negotiate" (SPNEGO whose underlying
    mechanism couldn't be resolved), "api_key", "other" (an Authorization header
    carrying a real but unnamed scheme, e.g. Digest), or "unauthenticated" (no
    auth observed).
    """
    auth_header = None
    for k, v in headers.items():
        if k.lower() == 'authorization':
            auth_header = v
            break

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
        # of an unnamed WWW-Authenticate challenge. The raw scheme still survives in
        # the finding's headers_snippet evidence.
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


def detect_auth_challenge(challenge: str) -> str:
    """Resolve a WWW-Authenticate challenge to the scheme the server demanded.

    Only the leading scheme token is examined; the challenge's parameters (realm,
    charset, an in-flight SPNEGO token) are left to the caller to retain as
    evidence. An unnamed scheme (e.g. Digest) is "other" -- a real but unnamed
    mechanism, not an absence of signal.
    """
    lower = (challenge or "").lower()
    if lower.startswith('basic'):
        return "basic"
    if lower.startswith('bearer'):
        return "bearer"
    if lower.startswith('ntlm'):
        return "ntlm"
    if lower.startswith('negotiate'):
        return "negotiate"
    return "other"


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


def _format_headers_snippet(headers: Dict[str, Any] | None, limit: int = 512) -> str:
    if not headers:
        return ""
    parts = [f"{k}: {v}" for k, v in headers.items()]
    text = "\n".join(parts)
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def _evidence_from(req: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'headers_snippet': _format_headers_snippet(req.get('request_headers')),
        'status_code': int(req.get('status', 0) or 0),
        'first_seen_on_page': req.get('source_url', '') or '',
    }


# Origin-level ranking for aggregate_by_origin: when an origin is seen with more
# than one authentication scheme across its requests, the highest-ranked scheme
# becomes the origin's label. Ordered so the weakest/most-notable schemes (Basic,
# NTLM) rank highest and "no auth observed" ranks lowest; a 401 challenge ranks as
# the scheme it demanded, so a demanded Basic/NTLM is never masked by an accepted
# credential on another endpoint of the same origin.
_AUTH_RANK = {
    "basic": 8,
    "ntlm": 8,
    "negotiate": 7,
    "other": 6,
    "unknown": 5,
    "kerberos": 4,
    "bearer": 3,
    "oauth": 2,
    "api_key": 1,
    "unauthenticated": 0,
}


def _auth_rank(value: str) -> int:
    """Rank an authentication tag by its scheme for origin aggregation.

    The scraper's tags are a closed set -- a detect_authentication tag, the scheme
    tag a 401 challenge resolved to, or an "oauth" IdP redirect -- and they are the
    keys of _AUTH_RANK, so the table is the whole classification and matching is
    exact. Those keys are also the tags translate.tag_to_auth_method maps to
    AuthMethod, so an origin's rank agrees with the scheme the FE will ultimately show.
    A scheme the server demanded therefore counts the same as one actually
    observed. Both an unnamed 401 challenge and an Authorization header carrying an
    unnamed scheme surface as "other", which ranks just above the "unknown"
    fallback (reached only by a tag outside the set). "other" still sits below
    negotiate and the blockers, so it never masks a more-notable demanded scheme,
    and (like every named scheme) outranks unauthenticated.
    """
    return _AUTH_RANK.get((value or "").strip().lower(), _AUTH_RANK["unknown"])


def aggregate_by_origin(requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group requests by origin and pick the most specific authentication seen.

    The key is the (scheme, host, port) triple rather than the hostname: each
    origin is a separate listener to publish, and "http://x" and "https://x" (or
    "x:8443") can be different services with different authentication. Requests
    whose URL has no origin are skipped.

    Retains a representative evidence sample (request headers, response status,
    first source page) for the request whose authentication classification "wins"
    so the FE can render its `evidence` block.
    """
    result_map: Dict[Origin, Dict[str, Any]] = {}
    for req in requests:
        origin = origin_of(req['url'])
        if origin is None:
            continue

        current_auth = req.get('authentication', 'unauthenticated')

        if origin not in result_map:
            entry = {
                'scheme': origin.scheme,
                'host': origin.host,
                'port': origin.port,
                'authentication': current_auth,
                'request_count': 1,
            }
            entry.update(_evidence_from(req))
            result_map[origin] = entry
            continue

        entry = result_map[origin]
        entry['request_count'] = int(entry.get('request_count', 1)) + 1

        existing_auth = entry['authentication']
        # Rank by scheme (_auth_rank): the most notable auth seen on any of the
        # origin's requests wins as its label. A strictly higher rank also brings
        # its evidence sample along; equal ranks keep the first request seen.
        if _auth_rank(current_auth) > _auth_rank(existing_auth):
            entry['authentication'] = current_auth
            entry.update(_evidence_from(req))

    return list(result_map.values())
