"""The URLs the API checks: an app's when it is created, and a registry
entry's, which an admin sets from the exposure console."""
import pytest
from pydantic import ValidationError

from api.models import CreateAppRequest, PatchPublishedOriginRequest


def _app(url: str) -> CreateAppRequest:
    return CreateAppRequest(name="Payroll", url=url, owner_ad_group="g")


@pytest.mark.parametrize("given, stored", [
    (" https://payroll.corp.internal ", "https://payroll.corp.internal"),
    ("http://payroll.corp.internal:8080/app/", "http://payroll.corp.internal:8080/app/"),
    # A scan may need to start on a particular page of a single-page app.
    ("https://payroll.corp.internal/#/login", "https://payroll.corp.internal/#/login"),
    ("https://payroll.corp.internal/start?tenant=a", "https://payroll.corp.internal/start?tenant=a"),
    ("http://[::1]:8080", "http://[::1]:8080"),
])
def test_an_app_url_is_kept_as_given(given, stored):
    assert _app(given).url == stored


@pytest.mark.parametrize("url", ["payroll.corp.internal", "ftp://x", "https://", "https://user:pw@x", "https://x:99999", ""])
def test_an_app_url_is_refused(url):
    with pytest.raises(ValidationError):
        _app(url)


def test_a_registry_url_must_be_https():
    # The app's VIP serves HTTPS; a browser blocks its calls to http:// as mixed content.
    assert PatchPublishedOriginRequest(url="https://P.example.com/").url == "https://p.example.com"
    with pytest.raises(ValidationError, match="https://"):
        PatchPublishedOriginRequest(url="http://p.example.com")
