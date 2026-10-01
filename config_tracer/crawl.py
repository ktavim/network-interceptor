"""Playwright crawler orchestration: visit pages, capture configs, discover links."""

import asyncio
import logging
import re
from urllib.parse import urljoin, urlparse

from playwright.async_api import Page, Response, async_playwright

from .capture import capture_response, process_js_captures, process_network_captures
from .dom import extract_from_dom
from .interact import _run_interactions
from .manifest import _probe_manifests
from .models import ConfigSource

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Crawler orchestrator
# ---------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    """Drop fragment and normalize trailing slash on path for dedupe purposes."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    # Reconstruct without fragment
    netloc = parsed.netloc
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme}://{netloc}{path}{query}"


async def _discover_links(page: Page, base_url: str) -> list[str]:
    """Pull a[href] values from the page; return absolute same-origin http(s) URLs."""
    try:
        hrefs = await page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.getAttribute('href'))"
        )
    except Exception:
        return []
    base_host = urlparse(base_url).netloc
    out: list[str] = []
    for href in hrefs:
        if not href:
            continue
        if href.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        abs_url = urljoin(base_url, href)
        parsed = urlparse(abs_url)
        if parsed.scheme not in ("http", "https"):
            continue
        if parsed.netloc != base_host:
            continue
        out.append(abs_url)
    return out
# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------

_LOGIN_URL_RE = re.compile(r"/(login|signin|sign-in|auth/(?:login|signin)|sso)\b", re.IGNORECASE)


def _check_auth_signal(seed_url: str, final_url: str, status: int | None,
                      www_authenticate: str | None) -> str | None:
    """Return a warning string if the seed page looks unauthenticated, else None."""
    seed_host = urlparse(seed_url).hostname or ""
    final_host = urlparse(final_url).hostname or ""
    if status == 401:
        return f"entry page returned 401 (URL: {final_url})."
    if www_authenticate:
        return f"entry page sent WWW-Authenticate: {www_authenticate} (URL: {final_url})."
    if seed_host and final_host and seed_host != final_host:
        return f"entry page redirected off-origin to {final_url}."
    if _LOGIN_URL_RE.search(final_url):
        return f"final URL looks like a login page: {final_url}."
    return None


async def _crawl_one_page(
    context,
    url: str,
    captured: list[tuple[str, str]],
    captured_js: list[tuple[str, str]],
    captured_urls: set[str],
    seen_urls: set[str],
    timeout: int,
    wait_after_load: int,
    interact_budget_ms: int,
    is_seed: bool = False,
) -> tuple[list[ConfigSource], list[str]]:
    """Visit one URL; return (dom_sources, discovered_links)."""
    page = await context.new_page()
    # Body reads are kicked off from the sync response hook; keep the tasks so
    # they can be awaited before the page closes instead of racing it.
    capture_tasks: set[asyncio.Task] = set()

    def _on_response(resp: Response) -> None:
        task = asyncio.ensure_future(
            capture_response(resp, captured, captured_js, seen_urls)
        )
        capture_tasks.add(task)
        task.add_done_callback(capture_tasks.discard)

    page.on("response", _on_response)

    log.info("Navigating to %s", url)
    response = None
    try:
        response = await page.goto(url, wait_until="networkidle", timeout=timeout)
    except Exception as e:
        log.warning("Navigation issue for %s: %s", url, e)

    if is_seed:
        status = response.status if response else None
        www_auth = response.headers.get("www-authenticate") if response else None
        signal = _check_auth_signal(url, page.url, status, www_auth)
        if signal:
            log.warning("%s The crawl runs anonymous, so configs behind the "
                        "login will not be seen.", signal)

    if wait_after_load > 0:
        await page.wait_for_timeout(wait_after_load)

    log.debug("Running interactions (budget %dms)", interact_budget_ms)
    await _run_interactions(page, interact_budget_ms)
    if wait_after_load > 0:
        await page.wait_for_timeout(wait_after_load)

    dom_sources = await extract_from_dom(page, captured_urls)

    discovered: list[str] = []
    try:
        discovered = await _discover_links(page, page.url)
    except Exception:
        pass

    if capture_tasks:
        try:
            await asyncio.wait_for(
                asyncio.gather(*capture_tasks, return_exceptions=True), timeout=2.0
            )
        except asyncio.TimeoutError:
            log.debug("Gave up waiting for %d in-flight capture(s) on %s",
                      len(capture_tasks), url)
    await page.close()
    return dom_sources, discovered


async def crawl(
    url: str | list[str],
    timeout: int = 30000,
    wait_after_load: int = 5000,
    interact_budget_ms: int = 8000,
    follow_links: bool = False,
    max_pages: int = 1,
) -> list[ConfigSource]:
    if isinstance(url, str):
        seeds = [url]
    else:
        seeds = list(url)
    if not seeds:
        return []

    captured: list[tuple[str, str]] = []
    captured_js: list[tuple[str, str]] = []
    # Dedup set: shared across page captures and the manifest probe so the
    # same chunk URL never appears twice in captured_js / captured_json.
    seen_urls: set[str] = set()
    all_dom_sources: list[ConfigSource] = []

    queue: list[str] = []
    visited: set[str] = set()
    for s in seeds:
        norm = _normalize_url(s)
        if norm not in visited:
            visited.add(norm)
            queue.append(s)

    async with async_playwright() as pw:
        # The worker owns shutdown; Playwright closing the browser on a signal would fail the scan.
        browser = await pw.chromium.launch(
            headless=True,
            handle_sigint=False,
            handle_sigterm=False,
            handle_sighup=False,
        )
        context = await browser.new_context()

        pages_visited = 0
        manifest_probed = False
        while queue and pages_visited < max_pages:
            current = queue.pop(0)
            captured_urls = {u for u, _ in captured}
            dom_sources, discovered = await _crawl_one_page(
                context=context,
                url=current,
                captured=captured,
                captured_js=captured_js,
                captured_urls=captured_urls,
                seen_urls=seen_urls,
                timeout=timeout,
                wait_after_load=wait_after_load,
                interact_budget_ms=interact_budget_ms,
                is_seed=(pages_visited == 0),
            )
            all_dom_sources.extend(dom_sources)
            pages_visited += 1

            # Manifest probe — once, after the first page renders, against the seed origin
            if not manifest_probed:
                manifest_probed = True
                added = await _probe_manifests(context, seeds[0], captured_js, captured, seen_urls)
                if added:
                    log.info("Manifest probe captured %d chunk(s)", added)

            if follow_links and pages_visited < max_pages:
                for link in discovered:
                    norm = _normalize_url(link)
                    if norm in visited:
                        continue
                    visited.add(norm)
                    queue.append(link)

        await browser.close()

    log.info("Captured %d JSON network responses across %d page(s)",
             len(captured), pages_visited)
    log.info("Captured %d JS bodies (chunks/manifests)", len(captured_js))

    network_sources = process_network_captures(captured)
    js_sources = process_js_captures(captured_js)
    return network_sources + js_sources + all_dom_sources
