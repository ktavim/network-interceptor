"""Network response interception: capture JSON/JS bodies and turn them into ConfigSources."""

import logging

from playwright.async_api import Response

from .extract import extract_urls_from_text, strip_js_block_comments, urls_from_payload
from .models import ConfigSource

MAX_PAYLOAD_BYTES = 5 * 1024 * 1024  # 5 MB

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Network interception
# ---------------------------------------------------------------------------

def _is_json_response(response: Response) -> bool:
    ct = response.headers.get("content-type", "")
    if "json" in ct:
        return True
    if response.url.split("?")[0].split("#")[0].endswith(".json"):
        return True
    return False


def _is_js_response(response: Response) -> bool:
    ct = response.headers.get("content-type", "").lower()
    if "javascript" in ct or "ecmascript" in ct:
        return True
    path = response.url.split("?")[0].split("#")[0]
    if path.endswith((".js", ".mjs", ".cjs")):
        return True
    return False


def _exceeds_size_limit(response: Response) -> bool:
    cl = response.headers.get("content-length", "")
    if cl.isdigit() and int(cl) > MAX_PAYLOAD_BYTES:
        return True
    return False


async def capture_response(
    response: Response,
    captured_json: list[tuple[str, str]],
    captured_js: list[tuple[str, str]],
    seen_urls: set[str],
) -> None:
    if response.status < 200 or response.status >= 300:
        return
    if response.url in seen_urls:
        return
    if _exceeds_size_limit(response):
        log.warning("Skipping response, too large: %s", response.url)
        return
    is_json = _is_json_response(response)
    is_js = not is_json and _is_js_response(response)
    if not (is_json or is_js):
        return
    try:
        body = await response.text()
        if len(body) > MAX_PAYLOAD_BYTES:
            log.warning("Skipping response, body too large: %s", response.url)
            return
        if is_json:
            captured_json.append((response.url, body))
        else:
            captured_js.append((response.url, body))
        seen_urls.add(response.url)
    except Exception:
        pass  # body unavailable (e.g. page navigated away)


def process_network_captures(captured: list[tuple[str, str]]) -> list[ConfigSource]:
    sources: list[ConfigSource] = []
    for url, body in captured:
        origin = f"network: {url}"
        urls = urls_from_payload(body, origin)
        if urls:
            sources.append(ConfigSource(origin=origin, urls_found=urls))
    return sources


def process_js_captures(captured: list[tuple[str, str]]) -> list[ConfigSource]:
    """Extract URLs from captured JS bodies via regex (no JSON parsing).

    Block comments are stripped first (see strip_js_block_comments), so URLs that
    live only in license banners don't get reported as service dependencies."""
    sources: list[ConfigSource] = []
    for url, body in captured:
        urls = extract_urls_from_text(strip_js_block_comments(body))
        if urls:
            sources.append(ConfigSource(
                origin=f"js: {url}",
                urls_found=urls,
            ))
    return sources
