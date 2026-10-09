"""Translate each scanner's raw output into the frontend's domain model."""
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from config_tracer.report import ScanReport, ServiceReport, UrlEvidence

from .enums import AuthMethod, Scanner, Severity, SourceKind

# urls.resource_type of a tracer row: a probe the tracer sent, where an
# interceptor row names what the browser was loading ("xhr", "script").
PROBE_RESOURCE_TYPE = "probe"

# The tracer's provenance kinds that name a URL after the colon. "dom:" names
# an element of the page instead.
_URL_SOURCE_KINDS = (SourceKind.network, SourceKind.js, SourceKind.redirect, SourceKind.synthesized)


def tag_to_auth_method(tag: str) -> AuthMethod:
    """Map the crawler's authentication tag to the FE enum.

    Every tag the crawler emits is verbatim an AuthMethod value, so the enum
    constructor is the whole mapping. Sources:
    - auth_analyzer.detect_authentication() — ntlm, kerberos, negotiate, basic, bearer, api_key, other, unauthenticated
    - auth_analyzer.detect_auth_challenge() — the same short tags for a 401's demanded scheme: basic, bearer, ntlm, kerberos, negotiate, other (raw challenge kept separately in 'auth_challenge')
    - interceptor._apply_redirect() — "oauth" for a redirect to an IdP (the target kept separately in 'redirect_url')
    - request_capture._on_request_failed() — "no_response" for a failed request that sent no credentials (the browser's error kept separately in 'failure_reason')

    "negotiate" means SPNEGO whose concrete mechanism was unresolvable: NTLM and
    Kerberos are already resolved to their own tags upstream, so it is not a
    shortfall of this mapping.

    Matching is exact. A string outside that set means a producer drifted from the
    FE vocabulary, and unknown (severity_for -> review) puts it in front of a human
    instead of guessing a scheme from a coincidental substring.
    """
    try:
        return AuthMethod((tag or "").strip().lower())
    except ValueError:
        return AuthMethod.unknown


def severity_for(auth_method: AuthMethod) -> Severity:
    """Severity of an origin's auth method for the F5 publish.

    A whitelist: only the named, supported schemes clear. A scheme known to
    be unsupported (NTLM, Basic) blocks, and so does "other", a real scheme
    the crawler could not name: not on the supported list means unsupported
    until someone names it in the detector. Everything else is review, what
    cannot be told yet -- "negotiate" is SPNEGO whose mechanism (Kerberos or
    NTLM) went unresolved, "no_response" is an origin none of whose requests
    got an answer, "dns_failed" is an origin whose host the tracer could not
    resolve, and "unknown" is an answer that names no scheme: from the tracer
    a bare 401, a coarse 4xx or a 5xx, from the interceptor a producer that
    drifted from the vocabulary. The manual auth-method override exists to
    fill in the last three. An AuthMethod added without a tier here lands on
    review as well, in front of a human, rather than clearing unexamined.
    """
    if auth_method in (AuthMethod.ntlm, AuthMethod.basic, AuthMethod.other):
        return Severity.blocker
    if auth_method in (
        AuthMethod.kerberos,
        AuthMethod.bearer,
        AuthMethod.oauth,
        AuthMethod.login_redirect,
        AuthMethod.api_key,
        AuthMethod.unauthenticated,
    ):
        return Severity.cleared
    return Severity.review


def service_to_row(scan_id: str, service: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a single aggregate_by_origin entry into a ServiceRow-ready dict.

    The row is the service as the interceptor alone sees it. core.jobs stores
    its verdict as the interceptor's finding for the origin and combines it
    with the other scanner's.
    """
    auth_method = tag_to_auth_method(service.get("authentication", ""))
    severity = severity_for(auth_method)
    return {
        "id": uuid.uuid4().hex,
        "scan_id": scan_id,
        "scheme": service["scheme"],
        "host": service["host"],
        "port": service["port"],
        "auth_method": auth_method.value,
        "severity": severity.value,
        "request_count": len(service.get("urls") or []),
        "ips": service.get("ips"),
        # Filled in by services_to_rows once the url rows have ids.
        "evidence_url_id": None,
        "excluded": False,
    }


def url_to_row(service_id: str, item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert one aggregate_by_origin per-request summary into a UrlRow-ready dict.

    `url` is required: a summary without it is a producer bug, like a service
    entry without its origin triple.
    """
    return {
        "id": uuid.uuid4().hex,
        "service_id": service_id,
        "scanner": Scanner.interceptor.value,
        "method": item.get("method", "") or "",
        "url": item["url"],
        "resource_type": item.get("resource_type", "") or "",
        "status_code": int(item.get("status", 0) or 0),
        "failure_reason": item.get("failure_reason") or None,
        "auth_method": tag_to_auth_method(item.get("authentication", "")).value,
        "sent_auth_scheme": item.get("sent_auth_scheme") or None,
        "auth_challenge": item.get("auth_challenge") or None,
        "redirect_url": item.get("redirect_url") or None,
        "page_url": item.get("page_url", "") or "",
        # The tracer's provenance; a captured request's is its page_url.
        "sources": [],
    }


def services_to_rows(
    scan_id: str, external_services: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """(service rows, url rows). Each url row carries the id of its service row,
    and each service row's `evidence_url_id` is the id of the url row at the
    service's `evidence_index` (None when the service names no such row).

    Built in one pass because the ids cross both ways: url rows need the
    service id minted in service_to_row, and the service row needs the id
    minted in url_to_row for its evidence row.
    """
    service_rows: List[Dict[str, Any]] = []
    url_rows: List[Dict[str, Any]] = []
    for service in external_services:
        service_row = service_to_row(scan_id, service)
        service_rows.append(service_row)
        evidence_index = service.get("evidence_index")
        for i, item in enumerate(service.get("urls") or []):
            row = url_to_row(service_row["id"], item)
            if i == evidence_index:
                service_row["evidence_url_id"] = row["id"]
            url_rows.append(row)
    return service_rows, url_rows


def _strip_url(url: str) -> str:
    # Imported here: the crawler package loads Playwright, and the API imports
    # this module without ever translating a scanner's output.
    from crawler.network.auth_analyzer import strip_url

    return strip_url(url)


def parse_source(source: str) -> Tuple[SourceKind, str]:
    """A tracer provenance string, one of urls.sources, as (kind, what it
    names): the URL of a config, bundle or probed URL, or for dom the page
    element, in prose.

    Strict, like the verdict in tracer_url_to_row: a string that names no kind
    of the tracer's is a producer that drifted, and raises ValueError here, at
    write time, rather than failing every read of its service's sources."""
    kind, sep, named = source.partition(": ")
    try:
        parsed = SourceKind(kind) if sep else None
    except ValueError:
        parsed = None
    # page is the interceptor's kind, never a stored string.
    if parsed is None or parsed is SourceKind.page:
        raise ValueError(f"tracer provenance outside the vocabulary: {source!r}")
    return parsed, named


def _strip_source(source: str) -> str:
    """A tracer provenance string with the URL it names stripped like urls.url.

    `redirect:` and `synthesized:` repeat a probed URL and `network:` and `js:`
    name a response the page loaded, so each can carry the query string that
    was stripped from the url column."""
    kind, named = parse_source(source)
    if kind in _URL_SOURCE_KINDS:
        return f"{kind.value}: {_strip_url(named)}"
    return source


def _redirect_url(evidence: UrlEvidence) -> Optional[str]:
    """A 3xx probe's Location as urls.redirect_url holds it: resolved against
    the probed URL, since the tracer keeps the header raw and it is often
    relative, then stripped. None for any other response, whatever it sent."""
    status = evidence.status_code
    if not evidence.location or status is None or not 300 <= status < 400:
        return None
    return _strip_url(urljoin(evidence.url, evidence.location))


def tracer_url_to_row(service_id: str, evidence: UrlEvidence) -> Dict[str, Any]:
    """Convert one URL of a tracer report into a UrlRow-ready dict: the probe
    the tracer sent it, in the columns of a request the interceptor captured.

    The verdict goes through AuthMethod(), not tag_to_auth_method: a value
    outside the combined vocabulary, or a URL the tracer never probed (None),
    raises ValueError instead of being stored as unknown.
    """
    return {
        "id": uuid.uuid4().hex,
        "service_id": service_id,
        "scanner": Scanner.tracer.value,
        # No request was sent to a URL whose host failed DNS.
        "method": evidence.http_method.value if evidence.http_method else "",
        # The tracer keeps a URL as the config spelled it, query string included.
        "url": _strip_url(evidence.url),
        "resource_type": PROBE_RESOURCE_TYPE,
        # 0 with a failure_reason, as for a request the browser got no answer to.
        "status_code": evidence.status_code or 0,
        "failure_reason": evidence.error or None,
        "auth_method": AuthMethod(evidence.detected_method).value,
        # The probes are anonymous.
        "sent_auth_scheme": None,
        "auth_challenge": evidence.www_authenticate or None,
        "redirect_url": _redirect_url(evidence),
        # A probe has no page; where the URL was found is in sources.
        "page_url": "",
        "sources": list(dict.fromkeys(_strip_source(s) for s in evidence.sources)),
    }


def _tracer_service_to_row(scan_id: str, service: ServiceReport) -> Dict[str, Any]:
    """The service as the tracer alone sees it, like service_to_row's for the interceptor."""
    auth_method = AuthMethod(service.auth_verdict)
    return {
        "id": uuid.uuid4().hex,
        "scan_id": scan_id,
        "scheme": service.origin.scheme,
        "host": service.origin.host,
        "port": service.origin.port,
        "auth_method": auth_method.value,
        "severity": severity_for(auth_method).value,
        "request_count": len(service.urls),
        # None, not []: the tracer resolved no address for a dns_failed service.
        "ips": list(service.ips) or None,
        # Filled in by tracer_report_to_rows once the url rows have ids.
        "evidence_url_id": None,
        "excluded": False,
    }


def tracer_report_to_rows(
    scan_id: str, report: ScanReport
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """(service rows, url rows) for a tracer report, in the shape
    services_to_rows returns for the interceptor.

    Each service row's `evidence_url_id` is the id of the url row for the
    service's `verdict_url`, the sample of the URLs that carry its verdict.
    The report's suspect URLs were never probed and have no rows.
    """
    service_rows: List[Dict[str, Any]] = []
    url_rows: List[Dict[str, Any]] = []
    for service in report.services:
        service_row = _tracer_service_to_row(scan_id, service)
        service_rows.append(service_row)
        verdict_url = service.verdict_url
        for evidence in service.urls:
            row = tracer_url_to_row(service_row["id"], evidence)
            # Matched before stripping: two of the service's URLs can strip to the same one.
            if evidence.url == verdict_url:
                service_row["evidence_url_id"] = row["id"]
            url_rows.append(row)
    return service_rows, url_rows
