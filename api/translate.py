"""Translate raw scraper output into the frontend's domain model."""
import uuid
from typing import Any, Dict, List, Tuple

from .models import AuthMethod, Severity


def tag_to_auth_method(tag: str) -> AuthMethod:
    """Map the scraper's authentication tag to the FE enum.

    Every tag the scraper emits is verbatim an AuthMethod value, so the enum
    constructor is the whole mapping. Sources:
    - auth_analyzer.detect_authentication() — ntlm, kerberos, negotiate, basic, bearer, api_key, other, unauthenticated
    - auth_analyzer.detect_auth_challenge() — the same short tags for a 401's demanded scheme: basic, bearer, ntlm, negotiate, other (raw challenge kept separately in 'auth_challenge')
    - interceptor._apply_idp_redirect() — "oauth" (the IdP host kept separately in 'idp_redirect')

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
    if auth_method in (AuthMethod.ntlm, AuthMethod.basic):
        return Severity.blocker
    if auth_method in (AuthMethod.negotiate, AuthMethod.unknown, AuthMethod.other):
        return Severity.review
    return Severity.cleared


def truncate_headers(headers: Dict[str, Any] | None, limit: int = 512) -> str:
    if not headers:
        return ""
    parts = [f"{k}: {v}" for k, v in headers.items()]
    text = "\n".join(parts)
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def service_to_finding_row(scan_id: str, service: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a single aggregate_by_origin entry into a FindingRow-ready dict."""
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
        "request_count": int(service.get("request_count", 1) or 1),
        "first_seen_on_page": service.get("first_seen_on_page", "") or "",
        "headers_snippet": service.get("headers_snippet", "") or "",
        "status_code": int(service.get("status_code", 0) or 0),
        "excluded": False,
    }


def url_to_row(finding_id: str, seq: int, item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert one aggregate_by_origin per-request summary into a UrlRow-ready dict.

    `url` is required: a summary without it is a producer bug, like a service
    entry without its origin triple.
    """
    return {
        "id": uuid.uuid4().hex,
        "finding_id": finding_id,
        "seq": seq,
        "method": item.get("method", "") or "",
        "url": item["url"],
        "resource_type": item.get("resource_type", "") or "",
        "status_code": int(item.get("status", 0) or 0),
        "auth_method": tag_to_auth_method(item.get("authentication", "")).value,
        "auth_challenge": item.get("auth_challenge") or None,
        "idp_redirect": item.get("idp_redirect") or None,
        "source_url": item.get("source_url", "") or "",
    }


def services_to_findings(
    scan_id: str, external_services: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """(finding rows, url rows). Each url row carries the id of its finding row.

    Built in one pass because the url rows need the finding ids minted in
    service_to_finding_row; `seq` restarts at 0 for every finding.
    """
    finding_rows: List[Dict[str, Any]] = []
    url_rows: List[Dict[str, Any]] = []
    for service in external_services:
        finding = service_to_finding_row(scan_id, service)
        finding_rows.append(finding)
        for seq, item in enumerate(service.get("urls") or []):
            url_rows.append(url_to_row(finding["id"], seq, item))
    return finding_rows, url_rows
