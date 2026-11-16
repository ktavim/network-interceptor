"""The URLs an admin sets from the exposure console: the app's, and a registry entry's."""
import pytest
from pydantic import ValidationError

from api.models import PatchAppRequest, PatchPublishedOriginRequest


@pytest.mark.parametrize("given, stored", [
    (" HTTPS://Payroll.Corp.internal/ ", "https://payroll.corp.internal"),
    ("http://payroll.corp.internal:8080/app/", "http://payroll.corp.internal:8080/app"),
    ("http://[::1]:8080", "http://[::1]:8080"),
])
def test_an_app_url_is_normalized(given, stored):
    assert PatchAppRequest(url=given).url == stored


@pytest.mark.parametrize("url", [
    "payroll.corp.internal", "ftp://x", "https://", "https://user:pw@x", "https://x/?a=1", "https://x/#top",
    "https://x:99999",
])
def test_an_app_url_is_refused(url):
    with pytest.raises(ValidationError):
        PatchAppRequest(url=url)


def test_a_registry_url_must_be_https():
    # The app's VIP serves HTTPS; a browser blocks its calls to http:// as mixed content.
    assert PatchPublishedOriginRequest(url="https://P.example.com/").url == "https://p.example.com"
    with pytest.raises(ValidationError, match="https://"):
        PatchPublishedOriginRequest(url="http://p.example.com")
