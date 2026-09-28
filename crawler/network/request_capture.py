"""Wire Playwright page/context events to the NetworkInterceptor, deduplicating by (method, URL)."""
import logging
from functools import partial

from playwright.async_api import BrowserContext, Page

from ..origin import origin_of
from .interceptor import NetworkInterceptor

logger = logging.getLogger(__name__)


class RequestCapture:
    """Bridge Playwright events to NetworkInterceptor with de-duplication."""

    def __init__(self, interceptor: NetworkInterceptor, start_url: str):
        self.interceptor = interceptor
        self.start_origin = origin_of(start_url)
        self.pending_requests: dict = {}
        self.captured_keys: set = set()
        # Keys whose only record so far is a failed request, mapped to that
        # record. A failure is not final: a later attempt at the same URL that
        # gets further replaces it (_replace_failed).
        self.failed_records: dict = {}

    def attach(self, page: Page, context: BrowserContext) -> None:
        """Attach listeners to the main page and future pages opened in the context."""
        self._setup_page(page)
        context.on('page', self._setup_page)

    def _is_external_url(self, url: str) -> bool:
        # Anything off the start origin is external -- including the start host on
        # another scheme or port, which is a separate listener to publish.
        return origin_of(url) != self.start_origin

    @staticmethod
    def _key(request) -> tuple:
        return (request.method, request.url)

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
        key = self._key(request)
        if key not in self.pending_requests:
            self.pending_requests[key] = await self.interceptor.handle_request(request, page.url)

    async def _on_response(self, response, page: Page) -> None:
        request = response.request
        if not self._is_external_url(request.url):
            return
        key = self._key(request)
        if key in self.captured_keys:
            return

        request_data = self.pending_requests.get(key)
        if not request_data:
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
        if not self._is_external_url(request.url):
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
            request_data = await self.interceptor.handle_request(request, page.url)

        failure = request.failure
        logger.debug("Request failed for %s %s: %s", request.method, request.url, failure)
        request_data['status'] = 0
        # The browser's error text, e.g. "net::ERR_NAME_NOT_RESOLVED".
        request_data['failure_reason'] = failure
        self.interceptor.requests.append(request_data)
        # Not captured_keys: a later attempt that gets a response replaces this.
        self.failed_records[key] = request_data

    async def _on_request_finished(self, request, page: Page) -> None:
        if not self._is_external_url(request.url):
            return
        key = self._key(request)
        if key in self.captured_keys:
            return

        request_data = self.pending_requests.get(key) or await self.interceptor.handle_request(request, page.url)

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
