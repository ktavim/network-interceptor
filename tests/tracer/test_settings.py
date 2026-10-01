"""ScanSettings.from_env: the tracer's tuning as the API's environment gives it."""

import pytest
from pydantic import ValidationError

from config_tracer.settings import ScanSettings


def test_unset_variables_leave_the_defaults():
    assert ScanSettings.from_env({}) == ScanSettings()
    assert ScanSettings.from_env({"DATABASE_URL": "postgresql://x", "SCAN_TIMEOUT_S": "5"}) == ScanSettings()


def test_each_field_is_read_from_its_variable():
    settings = ScanSettings.from_env({
        "SCAN_NAV_TIMEOUT_MS": "10000",
        "SCAN_WAIT_AFTER_LOAD_MS": "1000",
        "SCAN_INTERACT_BUDGET_MS": "2000",
        "SCAN_FOLLOW_LINKS": "true",
        "SCAN_MAX_PAGES": "7",
        "PROBE_TIMEOUT_S": "2.5",
        "PROBE_CONCURRENCY": "4",
        "DNS_TIMEOUT_S": "1.5",
        "DNS_CONCURRENCY": "8",
    })
    assert settings == ScanSettings(
        nav_timeout_ms=10000, wait_after_load_ms=1000, interact_budget_ms=2000,
        follow_links=True, max_pages=7, probe_timeout_s=2.5, probe_concurrency=4,
        dns_timeout_s=1.5, dns_concurrency=8,
    )
    # Every field has a variable: none is left that only code can set.
    assert settings.model_dump().keys() == ScanSettings.model_fields.keys()
    assert all(getattr(settings, field) != default for field, default in ScanSettings().model_dump().items())


def test_surrounding_whitespace_is_ignored():
    assert ScanSettings.from_env({"SCAN_MAX_PAGES": " 3 "}).max_pages == 3


def test_defaults_to_the_process_environment(monkeypatch):
    monkeypatch.setenv("SCAN_MAX_PAGES", "5")
    assert ScanSettings.from_env().max_pages == 5


@pytest.mark.parametrize("variable, value", [
    ("SCAN_MAX_PAGES", "0"),
    ("SCAN_MAX_PAGES", "many"),
    ("SCAN_MAX_PAGES", ""),
    ("PROBE_TIMEOUT_S", "-1"),
    ("SCAN_FOLLOW_LINKS", "perhaps"),
])
def test_value_its_field_refuses_raises(variable, value):
    with pytest.raises(ValidationError):
        ScanSettings.from_env({variable: value})
