"""DOM scanning: inline JSON scripts, global config assignments, referenced .json assets."""

import logging
import re
from urllib.parse import urljoin

from playwright.async_api import Page

from .extract import urls_from_payload
from .models import ConfigSource

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DOM scanning
# ---------------------------------------------------------------------------

# Regex to find JS variable assignments that look like config objects/arrays
CONFIG_ASSIGN_RE = re.compile(
    r'(?:window\.[\w.]+|(?:var|let|const)\s+\w+)\s*=\s*(\{[\s\S]*\}|\[[\s\S]*\])\s*;',
)


async def extract_from_dom(page: Page, captured_urls: set[str]) -> list[ConfigSource]:
    sources: list[ConfigSource] = []

    # Strategy A: <script type="application/json">
    for el in await page.query_selector_all('script[type="application/json"]'):
        text = (await el.inner_text()).strip()
        if not text:
            continue
        origin = "dom: <script type=\"application/json\">"
        urls = urls_from_payload(text, origin)
        if urls:
            sources.append(ConfigSource(origin=origin, urls_found=urls))

    # Strategy B: inline scripts with global variable assignments
    for el in await page.query_selector_all("script:not([src])"):
        script_type = await el.get_attribute("type")
        if script_type and script_type != "text/javascript":
            continue
        text = (await el.inner_text()).strip()
        if not text or len(text) < 10:
            continue
        for match in CONFIG_ASSIGN_RE.finditer(text):
            # Identify which variable was assigned
            assign_text = text[max(0, match.start() - 40):match.start() + 60]
            assign_label = assign_text.split("=")[0].strip()[-40:]
            origin = f"dom: inline script ({assign_label})"
            urls = urls_from_payload(match.group(1), origin)
            if urls:
                sources.append(ConfigSource(origin=origin, urls_found=urls))

    # Strategy C: <script src="*.json"> or <link href="*.json">
    for el in await page.query_selector_all(
        'script[src$=".json"], link[href$=".json"]'
    ):
        src = await el.get_attribute("src") or await el.get_attribute("href")
        if not src:
            continue
        abs_url = urljoin(page.url, src)
        if abs_url in captured_urls:
            continue  # already captured via network interception
        try:
            resp = await page.context.request.get(abs_url)
            body = await resp.text()
            origin = f"dom: referenced file {src}"
            urls = urls_from_payload(body, origin)
            if urls:
                sources.append(ConfigSource(origin=origin, urls_found=urls))
        except Exception as e:
            log.warning("Could not fetch %s: %s", abs_url, e)

    return sources
