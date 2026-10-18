"""Wire Playwright page/context events to the NetworkInterceptor, deduplicating by (method, stripped URL)."""
import logging
import weakref
from functools import partial
from typing import Optional

from playwright.async_api import BrowserContext, Page

from ..origin import origin_of
from .auth_analyzer import strip_url
from .interceptor import NetworkInterceptor
from .write_guard import BLOCKED_FAILURE_REASON, WriteGuard

logger = logging.getLogger(__name__)


class RequestCapture:
    """Bridge Playwright events to NetworkInterceptor with de-duplication."""

    def __init__(self, interceptor: NetworkInterceptor, start_url: str, write_guard: Optional[WriteGuard] = None):
        self.interceptor = interceptor
        self.start_origin = origin_of(start_url)
        self.write_guard = write_guard
        self.pending_requests: dict = {}
        self.captured_keys: set = set()
        # Keys whose only record so far is a failed request, mapped to that
        # record. A failure is not final: a later attempt at the same URL that
        # gets further replaces it (_replace_failed).
        self.failed_records: dict = {}
        # Requests judged at request time as not sent by the app
        # (_issued_by_app), so their later events skip them even once the page
        # is back on the app. By identity: every event hands over the same
        # Request object.
        self._foreign = weakref.WeakSet()

    def attach(self, page: Page, context: BrowserContext) -> None:
        """Attach listeners to the main page and future pages opened in the context."""
        self._setup_page(page)
        context.on('page', self._setup_page)

    def _is_external_url(self, url: str) -> bool:
        # Anything off the start origin is external -- including the start host on
        # another scheme or port, which is a separate listener to publish.
        return origin_of(url) != self.start_origin

    def _issued_by_app(self, request, page: Page) -> bool:
        """Whether a page on the start origin sent `request`.

        What an off-site page loads -- a GitHub tab a link opened, the page a
        click wandered to -- says nothing about what the app depends on. An
        iframe's requests count with the page embedding it: an embedded widget
        is a dependency of the app.

        A top-level navigation is not judged by page.url, which still names the
        page being left: following a link off-site is not a call the app
        makes. It counts only when it is a redirect hop from a start-origin
        request, as the app's 302 to its IdP is.
        """
        if self._is_main_frame_navigation(request, page):
            first = request
            while first.redirected_from is not None:
                first = first.redirected_from
            return not self._is_external_url(first.url)
        return not self._is_external_url(page.url)

    @staticmethod
    def _is_main_frame_navigation(request, page: Page) -> bool:
        try:
            return request.is_navigation_request() and request.frame == page.main_frame
        except Exception:
            # request.frame raises for a request with no frame, such as a
            # service worker's.
            return False

    @staticmethod
    def _key(request) -> tuple:
        # The URL as the record stores it (handle_request strips it), so one
        # record stands for every request it can't tell apart. Keyed on the full
        # URL, each analytics hit -- same endpoint, fresh query string -- would
        # add another identical record.
        return (request.method, strip_url(request.url))

    def _replace_failed(self, key: tuple) -> None:
        """Drop the failed record for `key`, if any, so the attempt being
        captured now takes its place -- e.g. a retry that got the 401 challenge
        the first, aborted attempt never saw."""
        failed = self.failed_records.pop(key, None)
        if failed is not None:
            # By identity: == would match any record with equal fields.
            self.interceptor.requests[:] = [r for r in self.interceptor.requests if r is not failed]

    def _setup_page(self, target_page: Page) -> None:
        # Each handler is bound to the page it listens on so it can read that
        # page's URL at the moment the event fires: that is the page a captured
        # request was issued from, including for pages opened in the context.
        target_page.on('request', partial(self._on_request, page=target_page))
        target_page.on('response', partial(self._on_response, page=target_page))
        target_page.on('requestfailed', partial(self._on_request_failed, page=target_page))
        target_page.on('requestfinished', partial(self._on_request_finished, page=target_page))

    async def _on_request(self, request, page: Page) -> None:
        if not self._is_external_url(request.url):
            return
        if not self._issued_by_app(request, page):
            self._foreign.add(request)
            return
        key = self._key(request)
        if key not in self.pending_requests:
            self.pending_requests[key] = await self.interceptor.handle_request(request, page.url)

    async def _on_response(self, response, page: Page) -> None:
        request = response.request
        if not self._is_external_url(request.url) or request in self._foreign:
            return
        key = self._key(request)
        if key in self.captured_keys:
            return

        request_data = self.pending_requests.get(key)
        if not request_data:
            # No request event was seen, so this is the first chance to judge it.
            if not self._issued_by_app(request, page):
                return
            request_data = await self.interceptor.handle_request(request, page.url)

        self._replace_failed(key)
        try:
            await self.interceptor.handle_response(request_data, response)
        except Exception as e:
            logger.error("Error handling response for %s %s: %s", request.method, request.url, e, exc_info=True)
        finally:
            self.captured_keys.add(key)
            self.pending_requests.pop(key, None)

    async def _on_request_failed(self, request, page: Page) -> None:
        # Foreign is checked before the pop below, which would otherwise take
        # the pending record of an app request for the same URL.
        if not self._is_external_url(request.url) or request in self._foreign:
            return
        key = self._key(request)
        # The record made when the request fired carries the page that issued
        # it. Reading page.url now could name the page a navigation moved on to,
        # and that navigation is often what aborted the request.
        request_data = self.pending_requests.pop(key, None)
        # Already answered, or already recorded as failed: one record per key.
        if key in self.captured_keys or key in self.failed_records:
            return
        if request_data is None:
            if not self._issued_by_app(request, page):
                return
            request_data = await self.interceptor.handle_request(request, page.url)

        if self.write_guard is not None and self.write_guard.was_blocked(request):
            failure = BLOCKED_FAILURE_REASON
        else:
            failure = request.failure
        logger.debug("Request failed for %s %s: %s", request.method, request.url, failure)
        request_data['status'] = 0
        # The browser's error text, e.g. "net::ERR_NAME_NOT_RESOLVED", or
        # BLOCKED_FAILURE_REASON for a write the guard aborted.
        request_data['failure_reason'] = failure
        # "unauthenticated" is a claim that the server answered a bare request,
        # which a failure cannot back. A scheme the request sent is still what
        # the client uses, so that label stands.
        if request_data['authentication'] == 'unauthenticated':
            request_data['authentication'] = 'no_response'
        self.interceptor.requests.append(request_data)
        # Not captured_keys: a later attempt that gets a response replaces this.
        self.failed_records[key] = request_data

    async def _on_request_finished(self, request, page: Page) -> None:
        if not self._is_external_url(request.url) or request in self._foreign:
            return
        key = self._key(request)
        if key in self.captured_keys:
            return

        request_data = self.pending_requests.get(key)
        if not request_data:
            if not self._issued_by_app(request, page):
                return
            request_data = await self.interceptor.handle_request(request, page.url)

        self._replace_failed(key)
        try:
            response = await request.response()
            if response is not None:
                try:
                    await self.interceptor.handle_response(request_data, response)
                except Exception as body_error:
                    logger.warning("Could not read body for %s %s: %s", request.method, request.url, body_error)
                    request_data['status'] = getattr(response, 'status', 0)
                    self.interceptor.requests.append(request_data)
            else:
                logger.debug("Request finished but no response available for %s %s",
                             request.method, request.url)
                request_data['status'] = 0
                self.interceptor.requests.append(request_data)
        except Exception as e:
            logger.debug("Request finished but response not accessible for %s %s: %s",
                         request.method, request.url, e)
            request_data['status'] = 0
            self.interceptor.requests.append(request_data)
        finally:
            self.captured_keys.add(key)
