"""Abort state-changing requests so the crawl does not write to the apps it scans.

The crawler fills every form it finds and clicks Save/Submit/Create; against a
real app that creates junk records, sends mail and opens tickets. Filtering
buttons by their text is a guess, while the request method is not, so with
write_policy "block" every request that can change server state is aborted
before it leaves the browser. That covers every origin, the scanned app's own
backend included, even though only external requests are recorded.

Let through:
- GET, HEAD and OPTIONS;
- anything while login is in progress (allow_writes());
- requests to the login URL or below it at any time: after the form itself is
  done, the app still POSTs to the IdP's token endpoint for the code exchange and
  for refreshes (Keycloak's sits under the realm URL);
- a GraphQL POST whose operations are all queries;
- a URL containing one of allow_write_patterns.

A blocked request still fires 'request' and 'requestfailed', so its origin,
method and sent auth scheme are recorded; only what the response would have told
(status, challenge, redirect) is lost. was_blocked() lets RequestCapture tell the
abort apart from a real network failure.
"""
import json
import logging
import re
import weakref
from contextlib import contextmanager
from typing import Optional

from playwright.async_api import BrowserContext, Request, Route

from config_loader import Config
from ..auth.login import is_login_url
from .auth_analyzer import strip_url

logger = logging.getLogger(__name__)

SAFE_METHODS = frozenset({'GET', 'HEAD', 'OPTIONS'})

# Recorded as a blocked request's 'failure_reason' in place of the browser's
# "net::ERR_BLOCKED_BY_CLIENT", which would read as an ad blocker.
BLOCKED_FAILURE_REASON = "blocked_by_write_guard"

_GRAPHQL_STRING = re.compile(r'"""[\s\S]*?"""|"(?:\\.|[^"\\\n])*"')
_GRAPHQL_COMMENT = re.compile(r'#[^\n]*')
_GRAPHQL_WRITE_KEYWORD = re.compile(r'\b(?:mutation|subscription)\b')
_GRAPHQL_READ_START = re.compile(r'(?:query|fragment)\b')


def _is_read_only_graphql_document(document) -> bool:
    """True when a GraphQL document holds only queries (and fragments).

    Conservative: any 'mutation' or 'subscription' token outside a string or
    comment counts as a write, so a field merely named "subscription" is blocked
    too. Blocking a read costs one request; letting a write through is the
    thing this module exists to prevent.
    """
    if not isinstance(document, str):
        return False
    document = _GRAPHQL_STRING.sub('""', document)
    document = _GRAPHQL_COMMENT.sub('', document).strip()
    if not document or _GRAPHQL_WRITE_KEYWORD.search(document):
        return False
    return document.startswith('{') or bool(_GRAPHQL_READ_START.match(document))


def is_read_only_graphql(post_data: Optional[str]) -> bool:
    """True for a JSON GraphQL body (single or batched) made only of queries.

    Only JSON bodies count: a raw form body such as "query=x&delete=1" also
    starts with the word "query". A persisted query that sends a hash and no
    document cannot be told apart from a mutation, so it is not read-only.
    """
    if not post_data:
        return False
    try:
        body = json.loads(post_data)
    except ValueError:
        return False
    operations = body if isinstance(body, list) else [body]
    return bool(operations) and all(
        isinstance(op, dict) and _is_read_only_graphql_document(op.get('query'))
        for op in operations
    )


def _post_data(request: Request) -> Optional[str]:
    try:
        return request.post_data
    except Exception:
        # A binary body that is not UTF-8 -- not a GraphQL query either way.
        return None


class WriteGuard:
    """Route handler that aborts state-changing requests under write_policy "block"."""

    def __init__(self, config: Config):
        self.enabled = config.write_policy == 'block'
        self.allow_patterns = [p.lower() for p in config.allow_write_patterns or ()]
        self.login = config.login
        self.blocked_count = 0
        self._login_in_progress = False
        # By identity: Playwright hands the route handler and the event
        # listeners the same Request object.
        self._blocked = weakref.WeakSet()

    async def attach(self, context: BrowserContext) -> None:
        if not self.enabled:
            logger.warning("write_policy is 'allow': the crawl may submit forms to the scanned app")
            return
        await context.route('**/*', self._handle_route)

    @contextmanager
    def allow_writes(self):
        """Let every request through for the duration, e.g. while logging in."""
        previous = self._login_in_progress
        self._login_in_progress = True
        try:
            yield
        finally:
            self._login_in_progress = previous

    def is_allowed(self, request: Request) -> bool:
        if request.method.upper() in SAFE_METHODS:
            return True
        if self._login_in_progress:
            return True
        url = request.url
        if self.login and is_login_url(url, self.login):
            return True
        url_lower = url.lower()
        if any(p in url_lower for p in self.allow_patterns):
            return True
        return is_read_only_graphql(_post_data(request))

    def was_blocked(self, request: Request) -> bool:
        return request in self._blocked

    async def _handle_route(self, route: Route) -> None:
        request = route.request
        if self.is_allowed(request):
            await route.fallback()
            return
        # Marked before the abort: 'requestfailed' fires as a result of it.
        self._blocked.add(request)
        self.blocked_count += 1
        logger.info("Write guard blocked %s %s", request.method, strip_url(request.url))
        await route.abort('blockedbyclient')
