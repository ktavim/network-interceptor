"""Translate raw crawler output into the frontend's domain model."""
import uuid
from typing import Any, Dict, List, Tuple

from .enums import AuthMethod, Severity


def tag_to_auth_method(tag: str) -> AuthMethod:
    """Map the crawler's authentication tag to the FE enum.

    Every tag the crawler emits is verbatim an AuthMethod value, so the enum
    constructor is the whole mapping. Sources:
    - auth_analyzer.detect_authentication() — ntlm, kerberos, negotiate, basic, bearer, api_key, other, unauthenticated
    - auth_analyzer.detect_auth_challenge() — the same short tags for a 401's demanded scheme: basic, bearer, ntlm, kerberos, negotiate, other (raw challenge kept separately in 'auth_challenge')
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
    """Severity of an origin's auth method for the F5 publish.

    Read as a whitelist: only the named, supported schemes clear. A scheme
    known to be unsupported (NTLM, Basic) blocks, and so does "other", a real
    scheme the crawler could not name: not on the supported list means
    unsupported until someone names it in the detector. Review is for what
    cannot be told yet -- "negotiate" is SPNEGO whose mechanism (Kerberos or
    NTLM) went unresolved, and "unknown" means a producer drifted from the
    vocabulary, which the manual auth-method override exists to fill in.
    """
    if auth_method in (AuthMethod.ntlm, AuthMethod.basic, AuthMethod.other):
        return Severity.blocker
    if auth_method in (AuthMethod.negotiate, AuthMethod.unknown):
        return Severity.review
    return Severity.cleared


def service_to_row(scan_id: str, service: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a single aggregate_by_origin entry into a ServiceRow-ready dict."""
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
        "method": item.get("method", "") or "",
        "url": item["url"],
        "resource_type": item.get("resource_type", "") or "",
        "status_code": int(item.get("status", 0) or 0),
        "auth_method": tag_to_auth_method(item.get("authentication", "")).value,
        "sent_auth_scheme": item.get("sent_auth_scheme") or None,
        "auth_challenge": item.get("auth_challenge") or None,
        "idp_redirect": item.get("idp_redirect") or None,
        "page_url": item.get("page_url", "") or "",
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
