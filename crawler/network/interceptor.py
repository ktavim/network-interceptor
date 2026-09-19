"""Network request/response interceptor for Playwright."""
import json
import logging
from typing import Any, Dict, List, Optional

from playwright.async_api import Request, Response

from . import auth_analyzer

logger = logging.getLogger(__name__)


class NetworkInterceptor:
    """Intercept and store network requests/responses."""

    def __init__(self):
        self.requests: List[Dict[str, Any]] = []
        self.source_url: str = ""

    async def handle_request(self, request: Request) -> Dict[str, Any]:
        return {
            'url': request.url,
            'method': request.method,
            'request_headers': request.headers,
            'post_data': await self._get_post_data(request),
            'resource_type': request.resource_type,
            'source_url': self.source_url,
            'authentication': auth_analyzer.detect_authentication(request.headers, request.url),
        }

    async def handle_response(
        self,
        request_data: Dict[str, Any],
        response: Optional[Response] = None,
    ) -> Dict[str, Any]:
        try:
            if response is None:
                raise ValueError("Response is None")
            if not hasattr(response, 'status'):
                raise ValueError(f"Response object is invalid: {type(response)}")

            status = response.status if hasattr(response, 'status') else 0
            try:
                headers = response.headers
                if hasattr(headers, '__await__'):
                    headers = await headers
            except Exception:
                headers = {}

            response_data = {
                'status': status,
                'response_headers': headers,
            }

            if status == 401:
                self._apply_auth_challenge(headers, request_data, response_data)

            if status in (301, 302, 303, 307, 308):
                self._apply_idp_redirect(headers, request_data, response_data)

            # Built as a separate dict and merged only once every field is
            # resolved, so a mid-flight failure leaves no partial response keys
            # on the request.
            request_data.update(response_data)
            self.requests.append(request_data)
            return request_data
        except Exception as e:
            logger.error("Error handling response for %s: %s", request_data.get('url'), e, exc_info=True)
            status = 0
            if response and hasattr(response, 'status'):
                try:
                    status = response.status
                except Exception:
                    status = 0

            request_data.update({
                'status': status,
                'response_error': str(e),
            })
            if request_data not in self.requests:
                self.requests.append(request_data)
            return request_data

    def _apply_auth_challenge(self, headers, request_data, response_data) -> None:
        auth_challenge = self._get_header_value(headers, 'WWW-Authenticate')
        if not auth_challenge:
            return
        response_data['auth_challenge'] = auth_challenge
        # This runs only on a 401, which means whatever credential the request
        # carried (if any) was rejected -- so the server's challenge, not the
        # failed sent scheme, is the authoritative label. Promote it even over a
        # concrete detected auth like "bearer": a rejected credential must not
        # masquerade as accepted. The label is the resolved scheme alone, while the
        # raw challenge lives in the 'auth_challenge' key set above for evidence.
        request_data['authentication'] = auth_analyzer.detect_auth_challenge(auth_challenge)

    def _apply_idp_redirect(self, headers, request_data, response_data) -> None:
        location = self._get_header_value(headers, 'Location')
        if not location:
            return
        idp = auth_analyzer.detect_idp_redirect(location)
        if idp:
            response_data['idp_redirect'] = idp
            # As in _apply_auth_challenge, the label carries only the resolved
            # scheme; the IdP host that matched lives in the 'idp_redirect' key
            # set above for evidence.
            request_data['authentication'] = "oauth"

    @staticmethod
    def _get_header_value(headers: Dict[str, str], name: str) -> Optional[str]:
        for k, v in headers.items():
            if k.lower() == name.lower():
                return v
        return None

    @staticmethod
    async def _get_post_data(request: Request) -> Optional[Dict[str, Any]]:
        if request.method not in ['POST', 'PUT', 'PATCH']:
            return None
        try:
            post_data = request.post_data
            if post_data:
                try:
                    return json.loads(post_data)
                except json.JSONDecodeError:
                    if 'application/x-www-form-urlencoded' in request.headers.get('content-type', ''):
                        from urllib.parse import parse_qs
                        return dict(parse_qs(post_data))
                    return {'raw': post_data}
        except Exception:
            pass
        return None

    def get_requests(self) -> List[Dict[str, Any]]:
        return self.requests.copy()

    def clear(self):
        self.requests.clear()
