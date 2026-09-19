"""Tests for api.translate."""
import pytest

from api.models import AuthMethod, Severity
from api.translate import service_to_finding_row, severity_for, tag_to_auth_method


class TestSeverityFor:
    @pytest.mark.parametrize("auth_method", [AuthMethod.ntlm, AuthMethod.basic])
    def test_blockers(self, auth_method):
        assert severity_for(auth_method) == Severity.blocker

    @pytest.mark.parametrize(
        "auth_method", [AuthMethod.negotiate, AuthMethod.unknown, AuthMethod.other]
    )
    def test_review(self, auth_method):
        assert severity_for(auth_method) == Severity.review

    @pytest.mark.parametrize(
        "auth_method",
        [
            AuthMethod.kerberos,
            AuthMethod.oauth,
            AuthMethod.bearer,
            AuthMethod.mtls,
            AuthMethod.unauthenticated,
        ],
    )
    def test_cleared(self, auth_method):
        assert severity_for(auth_method) == Severity.cleared

    def test_every_auth_method_is_mapped(self):
        # Guards against a new AuthMethod slipping through without a severity.
        for auth_method in AuthMethod:
            assert isinstance(severity_for(auth_method), Severity)


class TestTagToAuthMethod:
    def test_other_marker_maps_to_other(self):
        # The interceptor's else-branch 401 challenge -> AuthMethod.other.
        assert tag_to_auth_method("other") == AuthMethod.other

    def test_unclassified_stays_unknown(self):
        assert tag_to_auth_method("something weird") == AuthMethod.unknown


class TestServiceToFindingRow:
    def test_carries_the_origin_triple(self):
        row = service_to_finding_row("scan-1", {
            "scheme": "https",
            "host": "api.example.com",
            "port": 8443,
            "authentication": "basic",
            "request_count": 3,
        })
        assert row["scan_id"] == "scan-1"
        assert (row["scheme"], row["host"], row["port"]) == ("https", "api.example.com", 8443)
        assert row["auth_method"] == AuthMethod.basic.value
        assert row["severity"] == Severity.blocker.value
        assert row["request_count"] == 3

    def test_missing_origin_field_is_a_producer_bug(self):
        # scheme/host/port are NOT NULL identity columns: an entry without them
        # must fail loudly here rather than persist a blank origin.
        with pytest.raises(KeyError):
            service_to_finding_row("scan-1", {"host": "api.example.com", "authentication": "basic"})
