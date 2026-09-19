"""Slim navigation handler coordinating URL/DOM tracking and click handling."""
import logging
import re
from typing import Set

from playwright.async_api import Page, Locator

from config_loader import Config

from ..origin import origin_of
from . import element_classifier
from .dom_hasher import DOMHasher
from .form_filler import FormFiller
from .overlay_handler import OverlayHandler
from .selectors import MODAL_CONTAINER_SELECTORS

logger = logging.getLogger(__name__)


class NavigationHandler:
    """Handle smart navigation through website."""

    def __init__(self, config: Config, dom_hasher: DOMHasher = None):
        self.config = config
        self.visited_urls: Set[str] = set()
        self.current_depth = 0
        self.clicks_on_current_page = 0
        # Set when an intercepting modal can't be cleared by overlay handling, so
        # the remaining clicks on the page short-circuit instead of each paying a
        # full (and futile) overlay pass.
        self.page_overlay_blocked = False

        self.dom_hasher = dom_hasher or DOMHasher()
        self.form_filler = FormFiller(config)
        self.overlay = OverlayHandler(
            self.form_filler,
            self.dom_hasher,
            exclude_patterns=config.exclude_patterns,
        )

    @property
    def visited_dom_hashes(self) -> Set[str]:
        return self.dom_hasher.visited_dom_hashes

    @visited_dom_hashes.setter
    def visited_dom_hashes(self, value: Set[str]) -> None:
        self.dom_hasher.visited_dom_hashes = value

    @property
    def visited_overlay_hashes(self) -> Set[str]:
        return self.dom_hasher.visited_overlay_hashes

    @visited_overlay_hashes.setter
    def visited_overlay_hashes(self, value: Set[str]) -> None:
        self.dom_hasher.visited_overlay_hashes = value

    def _should_follow_url(self, url: str) -> bool:
        if not url or url.startswith('javascript:') or url.startswith('mailto:'):
            return False
        try:
            if origin_of(url) != origin_of(self.config.start_url):
                return False
            # Honor exclude_patterns at the URL level too. Element-click filtering
            # (is_destructive_action) skips logout/delete buttons, but raw <a href>
            # link-following only gates on this method, so without this check a
            # same-origin "/logout" link would still be navigated to.
            url_lower = url.lower()
            if any(p.lower() in url_lower for p in (self.config.exclude_patterns or ())):
                return False
            return True
        except Exception:
            return False

    async def get_clickable_elements(self, page: Page):
        return await element_classifier.get_clickable_elements(
            page,
            max_clicks=self.config.max_clicks_per_page,
            exclude_patterns=self.config.exclude_patterns,
        )

    async def fill_page_forms(self, page: Page, root=None):
        await self.form_filler.fill(page, root=root)

    async def get_dom_hash(self, page: Page) -> str:
        return await self.dom_hasher.get_dom_hash(page)

    async def get_overlay_hash(self, container) -> str:
        return await self.dom_hasher.get_overlay_hash(container)

    async def dismiss_calendar_overlay(self, page: Page) -> bool:
        return await self.overlay.dismiss_calendar_overlay(page)

    async def is_destructive_action(self, element, text: str = "") -> bool:
        return await element_classifier.is_destructive_action(
            element, text=text, exclude_patterns=self.config.exclude_patterns
        )

    async def navigate_to(self, page: Page, url: str, depth: int = 0) -> bool:
        if depth > self.config.max_depth:
            return False
        if url in self.visited_urls:
            return False
        if not self._should_follow_url(url):
            return False

        try:
            self.current_depth = depth
            self.clicks_on_current_page = 0
            self.page_overlay_blocked = False
            self.visited_urls.add(url)

            await page.goto(url, wait_until='networkidle', timeout=self.config.wait_timeout)
            await page.wait_for_timeout(self.config.network_idle_timeout)

            dom_hash = await self.get_dom_hash(page)
            if dom_hash and self.dom_hasher.is_dom_seen(dom_hash):
                return False

            if dom_hash:
                self.dom_hasher.mark_dom_seen(dom_hash)
            return True

        except Exception as e:
            logger.error("Navigation error to %s: %s", url, e)
            return False

    async def click_element(self, page: Page, element: Locator) -> bool:
        if self.clicks_on_current_page >= self.config.max_clicks_per_page:
            return False

        if self.page_overlay_blocked:
            logger.debug("Page blocked by an unclearable overlay; skipping click.")
            return False

        try:
            if not await element.is_visible():
                logger.debug("Element is not visible, skipping click.")
                return False

            try:
                await element.scroll_into_view_if_needed(timeout=5000)
                await page.wait_for_timeout(500)
            except Exception as scroll_err:
                logger.debug("Scroll failed: %s. Attempting click without scroll.", scroll_err)

            url_before = page.url

            try:
                await element.click(timeout=5000)
            except Exception as click_err:
                await self._recover_from_click_error(page, element, click_err)

            self.clicks_on_current_page += 1

            try:
                await page.wait_for_load_state('networkidle', timeout=5000)
            except Exception:
                await page.wait_for_timeout(1000)

            if url_before == page.url:
                await page.wait_for_timeout(300)

            return True

        except Exception as e:
            logger.error("Click error: %s", e)
            return False

    async def _recover_from_click_error(self, page: Page, element: Locator, click_err: Exception) -> None:
        error_msg = str(click_err)
        if 'intercepts pointer events' not in error_msg:
            try:
                await element.click(timeout=3000, force=True)
                return
            except Exception:
                raise click_err

        interceptor_match = re.search(
            r'<(\w+)\b',
            error_msg.split('intercepts pointer events')[0].rsplit('\n', 1)[-1],
        )
        interceptor_tag = interceptor_match.group(1).lower() if interceptor_match else ''

        if interceptor_tag in ('html', 'body'):
            logger.info("Click intercepted by <%s>, not a modal. Force-clicking.", interceptor_tag)
            await element.click(timeout=3000, force=True)
            return

        has_modal = await self._has_visible_modal(page)
        if has_modal:
            logger.warning("Element click intercepted by a modal. Attempting to interact with overlay...")
            await self.overlay.handle(page)
            try:
                await element.click(timeout=3000)
            except Exception:
                # Overlay handling did not clear the blocker. Re-running it for
                # every remaining element on the page would cost a full overlay
                # pass each (minutes on pages with a stuck widget like select2),
                # which reads as an infinite loop. Mark the page blocked so the
                # remaining clicks short-circuit, and move on.
                logger.warning(
                    "Overlay persisted after handling; marking page blocked and "
                    "skipping its remaining clicks."
                )
                self.page_overlay_blocked = True
                raise click_err
        else:
            logger.info("Click intercepted but no modal detected. Force-clicking.")
            await element.click(timeout=3000, force=True)

    async def _has_visible_modal(self, page: Page) -> bool:
        for selector in MODAL_CONTAINER_SELECTORS:
            try:
                els = await page.query_selector_all(selector)
                for el in els:
                    if await el.is_visible():
                        return True
            except Exception:
                continue
        return False

    def reset_page_counters(self):
        self.clicks_on_current_page = 0

    def reset_overlay_state(self) -> None:
        """Clear the per-page 'blocked by unclearable overlay' flag. Called when
        the crawler starts exploring a page (including after a click-induced
        navigation, which doesn't go through navigate_to)."""
        self.page_overlay_blocked = False

    def can_continue_navigation(self) -> bool:
        return self.current_depth < self.config.max_depth
