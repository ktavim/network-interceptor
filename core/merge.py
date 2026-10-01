"""Combine the two scanners' findings for one origin into the service's verdict.

Each scanner reduces an origin's URLs to one finding by its own rule: the
interceptor by crawler.network.auth_analyzer._AUTH_RANK, the tracer by
config_tracer.models._VERDICT_PRECEDENCE. The two orderings disagree on
no_response and unknown, each for a reason that holds for its own scanner, so
neither changes. This module only decides between two finished findings.

Pure: findings in, verdict out.
"""
from dataclasses import dataclass
from typing import Iterable, Optional

from .enums import AuthMethod, Scanner, Severity
from .translate import severity_for


@dataclass(frozen=True)
class Finding:
    """One scanner's verdict for an origin."""

    scanner: Scanner
    auth_method: AuthMethod
    evidence_url_id: Optional[str] = None
    # Whether this scanner resolved the origin's host to at least one address.
    has_ips: bool = False


@dataclass(frozen=True)
class Verdict:
    """A service's combined verdict. `evidence_url_id` is the winning finding's."""

    auth_method: AuthMethod
    severity: Severity
    evidence_url_id: Optional[str]


# Which of two scanners' findings labels the origin, highest first. Used only
# when both scanners have a finding and no refinement in _pick dropped one.
_CROSS_SCANNER_ORDER: tuple[AuthMethod, ...] = (
    # A blocker always wins.
    AuthMethod.ntlm,
    AuthMethod.basic,
    AuthMethod.other,
    # Above every cleared scheme: a SPNEGO challenge may be NTLM underneath.
    AuthMethod.negotiate,
    # A concrete scheme beats a non-answer, as both scanners' own rules say.
    # Otherwise every app with a token API would land on unknown: the tracer
    # HEADs the API base named in the config and gets a 404 or a bare 401,
    # while the interceptor watched the browser use a bearer token. The
    # tracer's unknown cannot hide NTLM or Basic, which announce themselves in
    # the challenge.
    AuthMethod.kerberos,
    AuthMethod.bearer,
    AuthMethod.oauth,
    AuthMethod.login_redirect,
    AuthMethod.api_key,
    # A non-answer beats unauthenticated: a probed URL that answered nothing
    # recognizable must not be hidden by open siblings. Among themselves, a
    # real response beats none, and no response beats no address.
    AuthMethod.unknown,
    AuthMethod.no_response,
    AuthMethod.dns_failed,
    AuthMethod.unauthenticated,
)

_RANK = {method: rank for rank, method in enumerate(_CROSS_SCANNER_ORDER)}

# What a SPNEGO challenge turns out to be once the mechanism is seen.
_SPNEGO_MECHANISMS = (AuthMethod.kerberos, AuthMethod.ntlm)


def _pick(interceptor: Finding, tracer: Finding) -> Finding:
    """The finding that labels an origin both scanners reported.

    Three refinements come before the order, each dropping a finding the other
    scanner has shown to be an artifact of how it looked. At most one applies.
    """
    observed, probed = interceptor.auth_method, tracer.auth_method

    # The same SPNEGO challenge, seen twice: one scanner saw which mechanism
    # was used and the other only the challenge. In practice the anonymous
    # probe is the one left at negotiate.
    if probed is AuthMethod.negotiate and observed in _SPNEGO_MECHANISMS:
        return interceptor
    if observed is AuthMethod.negotiate and probed in _SPNEGO_MECHANISMS:
        return tracer

    # The lookup worked for the browser, so the name does resolve.
    if probed is AuthMethod.dns_failed and interceptor.has_ips:
        return interceptor

    # The interceptor's per-origin no_response means every browser request to
    # the origin failed, usually net::ERR_ABORTED from a cancelled navigation
    # or a prefetch. An answer to the tracer shows the origin is reachable.
    if observed is AuthMethod.no_response and probed not in (
        AuthMethod.no_response,
        AuthMethod.dns_failed,
    ):
        return tracer

    # On a tie the interceptor's finding stands: observed traffic beats a probe.
    return tracer if _RANK[probed] < _RANK[observed] else interceptor


def merge_findings(findings: Iterable[Finding]) -> Verdict:
    """The combined verdict for one origin from its scanners' findings.

    A lone finding is the verdict. Two go through _pick. The severity is the
    winning method's, so it can come out lower than the losing finding's: when
    a refinement dropped that finding, or when its non-answer met a concrete
    cleared scheme. The losing finding is not lost; it stays on the service
    as that scanner's own finding.

    Raises ValueError for no findings, or two from one scanner: a service
    exists because a scanner found it, and each scanner reports an origin once.
    """
    by_scanner: dict[Scanner, Finding] = {}
    for finding in findings:
        if finding.scanner in by_scanner:
            raise ValueError(f"two findings from scanner {finding.scanner.value!r}")
        by_scanner[finding.scanner] = finding
    if not by_scanner:
        raise ValueError("no findings to merge")

    interceptor = by_scanner.get(Scanner.interceptor)
    tracer = by_scanner.get(Scanner.tracer)
    if interceptor is None:
        winner = tracer
    elif tracer is None:
        winner = interceptor
    else:
        winner = _pick(interceptor, tracer)
    return Verdict(
        auth_method=winner.auth_method,
        severity=severity_for(winner.auth_method),
        evidence_url_id=winner.evidence_url_id,
    )
