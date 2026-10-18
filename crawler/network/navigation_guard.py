"""Abort top-level navigations that would take a tab off the scanned app.

The crawler clicks buttons without knowing where they lead, and a script can
send the tab anywhere. Loading another site wastes the time it takes to load it
and come back, and runs that site's code under the scan's session. What that
page loads is already kept out of the results (RequestCapture._issued_by_app);
this keeps the browser from going there at all. Link hrefs are checked before
the click (NavigationHandler.should_click_href); this covers everything else.

Let through:
- any navigation inside an iframe: an embedded widget is part of the app page;
- navigations to the start origin, and to the login URL's origin, so an expired
  session can still be sent to its IdP;
- anything while login is in progress (allow_offsite()), for SSO hops between
  hosts;
- non-web schemes (blob:, data:, about:).

context.route only sees the first URL of a redirect chain, so the app's own 302
to another host still goes through. That is how most apps send a user to their
IdP, so it is left alone.
"""
import logging
from contextlib import contextmanager
from urllib.parse import urlparse

from playwright.async_api import BrowserContext, Request, Route

from config_loader import Config
from ..origin import origin_of
from .auth_analyzer import strip_url

logger = logging.getLogger(__name__)

_WEB_SCHEMES = frozenset({'http', 'https'})


def _is_new_tab_navigation(request: Request) -> bool:
    """A top-level navigation in a tab that doesn't exist yet: Playwright creates
    the frame only after the request, so request.frame raises."""
    try:
        request.frame
        return False
    except Exception:
        return request.is_navigation_request()


def _is_top_level_navigation(request: Request) -> bool:
    if not request.is_navigation_request():
        return False
    try:
        return request.frame.parent_frame is None
    except Exception:
        # A new tab's first navigation, which is top-level too.
        return True


class NavigationGuard:
    """Route handler that keeps every tab's top-level document on the app."""

    def __init__(self, config: Config):
        self.allowed_origins = {origin_of(config.start_url)}
        if config.login:
            self.allowed_origins.add(origin_of(config.login.login_url))
        self.allowed_origins.discard(None)
        self.blocked_count = 0
        self._offsite_allowed = False

    async def attach(self, context: BrowserContext) -> None:
        await context.route('**/*', self._handle_route)

    @contextmanager
    def allow_offsite(self):
        """Let every navigation through for the duration, e.g. while logging in."""
        previous = self._offsite_allowed
        self._offsite_allowed = True
        try:
            yield
        finally:
            self._offsite_allowed = previous

    def is_allowed(self, request: Request) -> bool:
        if self._offsite_allowed or not _is_top_level_navigation(request):
            return True
        if urlparse(request.url).scheme.lower() not in _WEB_SCHEMES:
            return True
        return origin_of(request.url) in self.allowed_origins

    async def _handle_route(self, route: Route) -> None:
        request = route.request
        if self.is_allowed(request):
            await route.fallback()
            return
        self.blocked_count += 1
        logger.info("Navigation guard blocked off-site navigation to %s", strip_url(request.url))
        # "aborted" cancels the navigation and leaves the tab on the page it was
        # on. A new tab cancelled that way is never reported to Playwright and
        # lingers unseen, so a new tab gets an error page instead: it then
        # surfaces as a 'page' event, and Mapper._handle_new_tab closes it.
        await route.abort('blockedbyclient' if _is_new_tab_navigation(request) else 'aborted')
