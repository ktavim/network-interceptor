"""Main mapping engine: orchestrates navigation, interception, and aggregation."""
import inspect
import logging
import os
from typing import Any, Awaitable, Callable, Dict, Optional, Union

from playwright.async_api import Browser, BrowserContext, Page, async_playwright

from config_loader import Config
from .auth import is_on_login_page, perform_login, storage_state_valid
from .navigation import NavigationHandler
from .navigation.dom_hasher import DOMHasher
from .navigation.selectors import INTERACTIVE_SELECTORS, POPUP_CONTAINER_SELECTORS
from .network import NetworkInterceptor, RequestCapture
from .network.auth_analyzer import aggregate_by_origin
from .origin import Origin, origin_of

logger = logging.getLogger(__name__)

EventCallback = Callable[[str, Dict[str, Any]], Union[None, Awaitable[None]]]


class Mapper:
    """Main mapping engine."""

    def __init__(self, config: Config, on_event: Optional[EventCallback] = None):
        self.config = config
        self.interceptor = NetworkInterceptor()
        self.dom_hasher = DOMHasher()
        self.navigator = NavigationHandler(config, self.dom_hasher)
        self.playwright = None
        self.browser: Browser = None
        self.context: BrowserContext = None
        self.page: Page = None
        self._capture: RequestCapture = None
        self._used_reused_storage: bool = False
        self._on_event: Optional[EventCallback] = on_event
        self._pages_visited: int = 0
        self._announced_origins: set[Origin] = set()

    async def _emit(self, event_type: str, payload: Dict[str, Any]) -> None:
        if not self._on_event:
            return
        try:
            result = self._on_event(event_type, payload)
            if inspect.isawaitable(result):
                await result
        except Exception as e:
            logger.warning("on_event callback failed for %s: %s", event_type, e)

    async def _record_page_visit(self, url: str, depth: int) -> None:
        self._pages_visited += 1
        await self._emit('page_visited', {'path': url, 'depth': depth})
        await self._announce_new_origins()
        await self._emit('scan_progress', {
            'pages': self._pages_visited,
            'services': len(self._announced_origins),
            'blockers': 0,
        })

    async def _announce_new_origins(self) -> None:
        try:
            seen_now = set()
            for req in self.interceptor.get_requests():
                origin = origin_of(req.get('url', ''))
                if origin:
                    seen_now.add(origin)
            new_origins = seen_now - self._announced_origins
            for origin in new_origins:
                self._announced_origins.add(origin)
                await self._emit('external_service_seen', origin._asdict())
        except Exception as e:
            logger.debug("announce_new_origins failed: %s", e)

    @property
    def pages_crawled(self) -> int:
        return self._pages_visited

    async def initialize(self) -> None:
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=['--disable-blink-features=AutomationControlled'],
        )

        context_kwargs: Dict[str, Any] = dict(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                       '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        )
        if (self.config.login
                and self.config.login.reuse_storage_state
                and storage_state_valid(self.config.login)):
            context_kwargs['storage_state'] = self.config.login.storage_state_path
            self._used_reused_storage = True
            logger.info("Reusing stored session from %s", self.config.login.storage_state_path)

        self.context = await self.browser.new_context(**context_kwargs)
        self.page = await self.context.new_page()

        self._capture = RequestCapture(self.interceptor, self.config.start_url)
        self._capture.attach(self.page, self.context)

    async def map_website(self) -> Dict[str, Any]:
        logger.info("Starting external-services mapping for: %s", self.config.start_url)

        if not await self.navigator.navigate_to(self.page, self.config.start_url, 0):
            logger.error("Failed to navigate to start URL")
            return {"external_services": [], "pages_crawled": 0}

        await self._ensure_authenticated(self.page)

        self.interceptor.source_url = self.config.start_url
        await self._explore_page(self.page, 0)

        external_services = aggregate_by_origin(self.interceptor.get_requests())
        logger.info("Mapping complete. Found %d external services.", len(external_services))

        # Emit per-service classification events for the SSE stream.
        for entry in external_services:
            await self._emit('auth_detected', {
                'scheme': entry['scheme'],
                'host': entry['host'],
                'port': entry['port'],
                'method': entry.get('authentication', ''),
            })

        return {"external_services": external_services, "pages_crawled": self._pages_visited}

    async def _ensure_authenticated(self, page: Page) -> None:
        cfg = self.config.login
        if not cfg or not is_on_login_page(page, cfg):
            return

        try:
            await perform_login(page, cfg, self.config.start_url)
        except Exception as e:
            if not self._used_reused_storage:
                raise
            logger.warning("Login failed with reused session (%s); discarding and retrying", e)
            try:
                os.remove(cfg.storage_state_path)
            except OSError:
                pass
            self._used_reused_storage = False
            await page.goto(cfg.login_url, wait_until='load', timeout=self.config.wait_timeout)
            await perform_login(page, cfg, self.config.start_url)

    async def _explore_page(self, page: Page, depth: int) -> None:
        if depth >= self.config.max_depth:
            return

        # Fresh page: clear any 'blocked by unclearable overlay' state carried over
        # from a previously stuck page (this path also covers click-induced
        # navigations, which don't run through navigator.navigate_to).
        self.navigator.reset_overlay_state()

        await self._ensure_authenticated(page)

        base_url = page.url
        logger.info("Exploring page at depth %d: %s", depth, base_url)
        await self._record_page_visit(base_url, depth)

        await self.navigator.fill_page_forms(page)

        clickable_elements = await self.navigator.get_clickable_elements(page)
        logger.info("Found %d clickable elements", len(clickable_elements))

        for i, element in enumerate(clickable_elements):
            if self.navigator.clicks_on_current_page >= self.config.max_clicks_per_page:
                break

            if page.url != base_url:
                logger.warning("Restoring state: Expected %s, got %s", base_url, page.url)
                try:
                    await page.goto(base_url, wait_until='networkidle')
                except Exception as e:
                    logger.error("Failed to restore state to %s: %s", base_url, e)
                    continue

            await self._log_click_target(element, i, len(clickable_elements), depth)
            self.interceptor.source_url = page.url

            clicked = await self.navigator.click_element(page, element)
            if not clicked:
                continue

            await page.wait_for_timeout(self.config.network_idle_timeout)

            current_url = page.url
            if current_url == base_url:
                await self._interact_with_new_elements(page, depth)
                current_url = page.url

            if current_url != base_url:
                await self._maybe_explore_new_url(page, current_url, depth)
                await self._return_to(page, base_url)

        await self._follow_links_on_page(page, depth)

    async def _log_click_target(self, element, i: int, total: int, depth: int) -> None:
        element_text = ""
        try:
            element_text = (await element.text_content() or "").strip()
            if not element_text:
                element_text = (await element.get_attribute('aria-label') or "").strip()
            if not element_text:
                element_text = (await element.get_attribute('title') or "").strip()
        except Exception:
            pass
        label = f" ('{element_text[:30]}')" if element_text else ""
        logger.debug("Clicking element %d/%d of depth %d%s", i + 1, total, depth, label)

    async def _maybe_explore_new_url(self, page: Page, current_url: str, depth: int) -> None:
        should_follow = self.navigator._should_follow_url(current_url)
        if should_follow and current_url not in self.navigator.visited_urls:
            dom_hash = await self.dom_hasher.get_dom_hash(page)
            if dom_hash and self.dom_hasher.is_dom_seen(dom_hash):
                logger.debug("Skipping duplicate page (DOM hash match): %s", current_url)
                return
            if dom_hash:
                self.dom_hasher.mark_dom_seen(dom_hash)
            self.navigator.visited_urls.add(current_url)
            saved_clicks = self.navigator.clicks_on_current_page
            self.navigator.clicks_on_current_page = 0
            await self._explore_page(page, depth + 1)
            self.navigator.clicks_on_current_page = saved_clicks
        elif not should_follow:
            logger.debug("Skipping external/excluded URL: %s", current_url)

    async def _return_to(self, page: Page, base_url: str) -> None:
        try:
            await page.go_back(wait_until='load', timeout=self.config.wait_timeout)
            await page.wait_for_timeout(1000)
        except Exception as e:
            logger.warning("Could not go back: %s", e)
            try:
                if page.url != base_url:
                    await page.goto(base_url, wait_until='networkidle')
            except Exception:
                pass

    async def _interact_with_new_elements(self, page: Page, depth: int) -> None:
        if await self.navigator.dismiss_calendar_overlay(page):
            logger.debug("Dismissed calendar overlay after click")
            return

        base_url = page.url

        for selector in POPUP_CONTAINER_SELECTORS:
            try:
                containers = await page.query_selector_all(selector)
                for container in containers:
                    if not await container.is_visible():
                        continue

                    interactive = await container.query_selector_all(INTERACTIVE_SELECTORS)
                    if not interactive:
                        continue

                    overlay_hash = await self.dom_hasher.get_overlay_hash(container)
                    if self.dom_hasher.is_overlay_seen(overlay_hash):
                        logger.debug("Skipping already-seen overlay (hash: %s)", overlay_hash[:8])
                        continue
                    self.dom_hasher.mark_overlay_seen(overlay_hash)

                    await self.navigator.fill_page_forms(page, root=container)

                    logger.debug("Found popup/menu with %d interactive elements", len(interactive))
                    for el in interactive:
                        await self._click_popup_element(page, el, base_url, depth)
                    return
            except Exception:
                continue

    async def _click_popup_element(self, page: Page, el, base_url: str, depth: int) -> None:
        try:
            if not await el.is_visible():
                return
            if await self.navigator.is_destructive_action(el):
                return

            label = ''
            try:
                label = (await el.text_content() or '').strip()
            except Exception:
                pass
            logger.debug("  Clicking popup element: '%s'", label[:30])

            self.interceptor.source_url = page.url
            await el.click(timeout=3000)
            await page.wait_for_timeout(self.config.network_idle_timeout)

            if page.url != base_url:
                await self._maybe_explore_new_url(page, page.url, depth)
                await self._return_to(page, base_url)
        except Exception as e:
            logger.warning("  Could not click popup element: %s", e)

    async def _follow_links_on_page(self, page: Page, depth: int) -> None:
        if depth >= self.config.max_depth:
            return

        try:
            # Snapshot hrefs as strings up front. Navigating to one link destroys
            # the page's execution context and invalidates every live ElementHandle,
            # so holding handles across a navigation would make each later access
            # raise "Execution context was destroyed".
            #
            # Read the resolved el.href (absolute) rather than the raw attribute so
            # same-host relative links (e.g. Confluence's "/display/...") are followed
            # instead of being rejected by _should_follow_url, which compares netloc
            # and would treat a relative URL as host-less. el.href also honours any
            # <base> tag, matching what a real click would navigate to.
            hrefs = await page.eval_on_selector_all(
                'a[href]:not([class*="skip-link"])',
                'els => els.map(el => el.href)',
            )
            for href in hrefs[:10]:
                try:
                    if not href or href in self.navigator.visited_urls:
                        continue
                    if not self.navigator._should_follow_url(href):
                        continue

                    self.interceptor.source_url = page.url

                    if await self.navigator.navigate_to(page, href, depth + 1):
                        saved_clicks = self.navigator.clicks_on_current_page
                        self.navigator.clicks_on_current_page = 0
                        await self._explore_page(page, depth + 1)
                        self.navigator.clicks_on_current_page = saved_clicks
                        if depth > 0:
                            try:
                                await page.go_back(wait_until='load', timeout=self.config.wait_timeout)
                                await page.wait_for_timeout(1000)
                            except Exception as e:
                                logger.warning("Could not go back from %s: %s", href, e)
                except Exception as e:
                    logger.error("Error processing link: %s", e)
                    continue
        except Exception as e:
            logger.error("Error following links: %s", e)

    async def cleanup(self) -> None:
        if self.page:
            await self.page.close()
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
