"""Wire Playwright page/context events to the NetworkInterceptor, deduplicating by (method, URL)."""
import logging

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

    def _setup_page(self, target_page: Page) -> None:
        target_page.on('request', self._on_request)
        target_page.on('response', self._on_response)
        target_page.on('requestfailed', self._on_request_failed)
        target_page.on('requestfinished', self._on_request_finished)

    async def _on_request(self, request) -> None:
        if not self._is_external_url(request.url):
            return
        key = self._key(request)
        if key not in self.pending_requests:
            self.pending_requests[key] = await self.interceptor.handle_request(request)

    async def _on_response(self, response) -> None:
        request = response.request
        if not self._is_external_url(request.url):
            return
        key = self._key(request)
        if key in self.captured_keys:
            return

        request_data = self.pending_requests.get(key)
        if not request_data:
            request_data = await self.interceptor.handle_request(request)

        try:
            await self.interceptor.handle_response(request_data, response)
        except Exception as e:
            logger.error("Error handling response for %s %s: %s", request.method, request.url, e, exc_info=True)
        finally:
            self.captured_keys.add(key)
            self.pending_requests.pop(key, None)

    async def _on_request_failed(self, request) -> None:
        if not self._is_external_url(request.url):
            return
        key = self._key(request)
        if key in self.captured_keys:
            return

        request_data = await self.interceptor.handle_request(request)
        request_data.update({
            'status': 0,
            'response_error': 'Request failed',
        })
        self.interceptor.requests.append(request_data)
        self.captured_keys.add(key)

    async def _on_request_finished(self, request) -> None:
        if not self._is_external_url(request.url):
            return
        key = self._key(request)
        if key in self.captured_keys:
            return

        request_data = self.pending_requests.get(key) or await self.interceptor.handle_request(request)

        try:
            response = await request.response()
            if response is not None:
                try:
                    await self.interceptor.handle_response(request_data, response)
                except Exception as body_error:
                    logger.warning("Could not read body for %s %s: %s", request.method, request.url, body_error)
                    request_data.update({
                        'status': getattr(response, 'status', 0),
                        'response_error': f'Body not available: {body_error}',
                    })
                    self.interceptor.requests.append(request_data)
            else:
                request_data.update({
                    'status': 0,
                    'response_note': 'Request finished but no response available',
                })
                self.interceptor.requests.append(request_data)
        except Exception as e:
            request_data.update({
                'status': 0,
                'response_note': f'Request finished but response not accessible: {e}',
            })
            self.interceptor.requests.append(request_data)
        finally:
            self.captured_keys.add(key)
