"""Tests for core.merge: the cross-scanner verdict for one origin."""
import itertools

import pytest

from core.enums import AuthMethod, Scanner, Severity
from core.merge import _CROSS_SCANNER_ORDER, Finding, Verdict, merge_findings
from core.translate import severity_for

BLOCKERS = (AuthMethod.ntlm, AuthMethod.basic, AuthMethod.other)
# A scheme that was actually named and clears the publish.
CONCRETE_CLEARED = (
    AuthMethod.kerberos,
    AuthMethod.bearer,
    AuthMethod.oauth,
    AuthMethod.login_redirect,
    AuthMethod.api_key,
)
NON_ANSWERS = (AuthMethod.unknown, AuthMethod.no_response, AuthMethod.dns_failed)

_SEVERITY_ORDER = (Severity.cleared, Severity.review, Severity.blocker)


def _interceptor(auth_method: AuthMethod, has_ips: bool = False) -> Finding:
    return Finding(Scanner.interceptor, auth_method, "interceptor-url", has_ips)


def _tracer(auth_method: AuthMethod) -> Finding:
    return Finding(Scanner.tracer, auth_method, "tracer-url")


def _merge(observed: AuthMethod, probed: AuthMethod, has_ips: bool = False) -> Verdict:
    return merge_findings([_interceptor(observed, has_ips), _tracer(probed)])


class TestOneFinding:
    @pytest.mark.parametrize("scanner", list(Scanner))
    @pytest.mark.parametrize("auth_method", list(AuthMethod))
    def test_the_finding_is_the_verdict(self, scanner, auth_method):
        verdict = merge_findings([Finding(scanner, auth_method, "url-1")])
        assert verdict == Verdict(auth_method, severity_for(auth_method), "url-1")

    def test_a_finding_without_evidence_points_nowhere(self):
        verdict = merge_findings([Finding(Scanner.tracer, AuthMethod.bearer)])
        assert verdict.evidence_url_id is None


class TestSpnegoRefinement:
    def test_kerberos_drops_the_probes_negotiate(self):
        # By the order alone negotiate would win and put the origin on review.
        verdict = _merge(AuthMethod.kerberos, AuthMethod.negotiate)
        assert verdict == Verdict(AuthMethod.kerberos, Severity.cleared, "interceptor-url")

    def test_ntlm_drops_the_probes_negotiate(self):
        verdict = _merge(AuthMethod.ntlm, AuthMethod.negotiate)
        assert verdict == Verdict(AuthMethod.ntlm, Severity.blocker, "interceptor-url")

    def test_it_works_from_either_side(self):
        verdict = _merge(AuthMethod.negotiate, AuthMethod.ntlm)
        assert verdict == Verdict(AuthMethod.ntlm, Severity.blocker, "tracer-url")

    @pytest.mark.parametrize("cleared", [*CONCRETE_CLEARED[1:], AuthMethod.unauthenticated])
    def test_negotiate_still_outranks_every_other_cleared_scheme(self, cleared):
        # Nothing resolved the mechanism, so it may still be NTLM underneath.
        assert _merge(cleared, AuthMethod.negotiate) == Verdict(
            AuthMethod.negotiate, Severity.review, "tracer-url"
        )


class TestDnsFailedRefinement:
    def test_dropped_when_the_interceptor_resolved_the_host(self):
        verdict = _merge(AuthMethod.unauthenticated, AuthMethod.dns_failed, has_ips=True)
        assert verdict == Verdict(AuthMethod.unauthenticated, Severity.cleared, "interceptor-url")

    def test_stands_when_the_interceptor_has_no_ips_either(self):
        verdict = _merge(AuthMethod.unauthenticated, AuthMethod.dns_failed)
        assert verdict == Verdict(AuthMethod.dns_failed, Severity.review, "tracer-url")

    def test_dropped_even_for_an_interceptor_no_response(self):
        # The host resolved for the browser but nothing answered it: the
        # interceptor's finding is the one that describes the origin.
        verdict = _merge(AuthMethod.no_response, AuthMethod.dns_failed, has_ips=True)
        assert verdict == Verdict(AuthMethod.no_response, Severity.review, "interceptor-url")


class TestInterceptorNoResponseRefinement:
    @pytest.mark.parametrize(
        "answer",
        [m for m in AuthMethod if m not in (AuthMethod.no_response, AuthMethod.dns_failed)],
    )
    def test_dropped_when_the_tracer_got_an_answer(self, answer):
        verdict = _merge(AuthMethod.no_response, answer)
        assert verdict == Verdict(answer, severity_for(answer), "tracer-url")

    def test_an_open_origin_is_not_held_for_review_by_aborted_requests(self):
        # The case the refinement exists for: by the order alone the
        # interceptor's no_response would outrank the tracer's unauthenticated.
        verdict = _merge(AuthMethod.no_response, AuthMethod.unauthenticated)
        assert verdict.severity == Severity.cleared

    @pytest.mark.parametrize("no_answer", [AuthMethod.no_response, AuthMethod.dns_failed])
    def test_stands_when_the_tracer_got_no_answer_either(self, no_answer):
        verdict = _merge(AuthMethod.no_response, no_answer)
        assert verdict == Verdict(AuthMethod.no_response, Severity.review, "interceptor-url")

    def test_the_tracers_no_response_is_not_dropped(self):
        # One way only: a probe that timed out is a URL nobody saw, and the
        # interceptor's open traffic must not hide it.
        verdict = _merge(AuthMethod.unauthenticated, AuthMethod.no_response)
        assert verdict == Verdict(AuthMethod.no_response, Severity.review, "tracer-url")


class TestCrossScannerOrder:
    def test_ranks_the_whole_vocabulary_once(self):
        assert len(_CROSS_SCANNER_ORDER) == len(AuthMethod)
        assert set(_CROSS_SCANNER_ORDER) == set(AuthMethod)

    def test_token_api(self):
        # The tracer HEADs the API base from the config and gets a 404 or a
        # bare 401; the interceptor watched the browser use a bearer token.
        verdict = _merge(AuthMethod.bearer, AuthMethod.unknown)
        assert verdict == Verdict(AuthMethod.bearer, Severity.cleared, "interceptor-url")

    @pytest.mark.parametrize("scheme", CONCRETE_CLEARED)
    @pytest.mark.parametrize("non_answer", NON_ANSWERS)
    def test_a_concrete_scheme_beats_a_non_answer(self, scheme, non_answer):
        assert _merge(scheme, non_answer).auth_method == scheme
        assert _merge(non_answer, scheme).auth_method == scheme

    @pytest.mark.parametrize("non_answer", NON_ANSWERS)
    def test_a_tracer_non_answer_beats_unauthenticated(self, non_answer):
        verdict = _merge(AuthMethod.unauthenticated, non_answer)
        assert verdict == Verdict(non_answer, Severity.review, "tracer-url")

    @pytest.mark.parametrize("blocker", BLOCKERS)
    @pytest.mark.parametrize("other", list(AuthMethod))
    @pytest.mark.parametrize("has_ips", [False, True])
    def test_a_blocker_always_wins(self, blocker, other, has_ips):
        assert _merge(blocker, other, has_ips).severity == Severity.blocker
        assert _merge(other, blocker, has_ips).severity == Severity.blocker

    @pytest.mark.parametrize("auth_method", list(AuthMethod))
    def test_a_tie_goes_to_the_interceptor(self, auth_method):
        # Observed traffic beats a probe.
        assert _merge(auth_method, auth_method).evidence_url_id == "interceptor-url"

    @pytest.mark.parametrize(
        "observed, probed, has_ips",
        list(itertools.product(AuthMethod, AuthMethod, [False, True])),
    )
    def test_severity_drops_below_a_finding_only_for_the_stated_reasons(
        self, observed, probed, has_ips
    ):
        verdict = _merge(observed, probed, has_ips)
        won_by_tracer = verdict.evidence_url_id == "tracer-url"
        winner, loser = (probed, observed) if won_by_tracer else (observed, probed)
        assert verdict.auth_method == winner
        assert verdict.severity == severity_for(winner)

        if _SEVERITY_ORDER.index(severity_for(loser)) <= _SEVERITY_ORDER.index(verdict.severity):
            return
        spnego_resolved = loser is AuthMethod.negotiate and winner is AuthMethod.kerberos
        lookup_worked = not won_by_tracer and loser is AuthMethod.dns_failed and has_ips
        origin_answered = won_by_tracer and loser is AuthMethod.no_response
        non_answer_met_a_scheme = loser in NON_ANSWERS and winner in CONCRETE_CLEARED
        assert spnego_resolved or lookup_worked or origin_answered or non_answer_met_a_scheme


class TestInvalidInput:
    def test_no_findings(self):
        with pytest.raises(ValueError):
            merge_findings([])

    def test_two_findings_from_one_scanner(self):
        with pytest.raises(ValueError):
            merge_findings([_tracer(AuthMethod.bearer), _tracer(AuthMethod.unknown)])
