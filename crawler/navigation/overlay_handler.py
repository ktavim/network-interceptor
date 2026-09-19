"""Handle modal dialogs, popups, and calendar overlays."""
import logging
from typing import Iterable

from playwright.async_api import Page

from .dom_hasher import DOMHasher
from .element_classifier import is_destructive_action, neutralize_dropdown_masks
from .form_filler import FormFiller
from .selectors import (
    AFFIRMATIVE_ACTION_SELECTORS,
    BACKDROP_SELECTORS,
    CALENDAR_OVERLAY_SELECTORS,
    DISMISS_SELECTORS,
    DRAWER_OVERLAY_SELECTORS,
    INTERACTIVE_SELECTORS,
    MODAL_CONTAINER_SELECTORS,
)

logger = logging.getLogger(__name__)


class OverlayHandler:
    """Detect and interact with modals, popups, and calendar overlays."""

    def __init__(
        self,
        form_filler: FormFiller,
        dom_hasher: DOMHasher = None,
        exclude_patterns: Iterable[str] = (),
    ):
        self.form_filler = form_filler
        self.exclude_patterns = list(exclude_patterns)
        self.dom_hasher = dom_hasher or DOMHasher()

    async def is_calendar_overlay(self, container) -> bool:
        """Check if a container element looks like a calendar overlay."""
        try:
            return await container.evaluate('''(el) => {
                const cls = (el.className || '').toLowerCase();
                const calendarPatterns = ['calendar', 'datepicker', 'date-picker', 'flatpickr'];
                if (calendarPatterns.some(p => cls.includes(p))) return true;
                const grid = el.querySelector('[role="grid"]');
                if (grid) {
                    const cells = grid.querySelectorAll('td, [role="gridcell"]');
                    let dayCount = 0;
                    cells.forEach(c => {
                        const num = parseInt(c.textContent.trim());
                        if (num >= 1 && num <= 31) dayCount++;
                    });
                    if (dayCount >= 7) return true;
                }
                return false;
            }''')
        except Exception:
            return False

    async def dismiss_calendar_overlay(self, page: Page) -> bool:
        """Detect and dismiss any visible calendar/datepicker overlay.

        Returns True only when the overlay is actually gone afterwards. A matched
        overlay that survives the dismissal attempt (a false positive, or a widget
        that ignores Escape) reports False so callers don't treat the page as
        unblocked and skip handling the real modal.
        """
        for selector in CALENDAR_OVERLAY_SELECTORS:
            try:
                elements = await page.query_selector_all(selector)
                for el in elements:
                    try:
                        if not await el.is_visible():
                            continue
                        if not await self.is_calendar_overlay(el):
                            continue

                        logger.debug("Calendar overlay detected, dismissing...")
                        await page.keyboard.press('Escape')
                        await page.wait_for_timeout(300)

                        if await self._overlay_still_visible(el):
                            await page.mouse.click(0, 0)
                            await page.wait_for_timeout(300)
                            if await self._overlay_still_visible(el):
                                # Still blocking — don't claim success.
                                continue

                        return True
                    except Exception:
                        continue
            except Exception:
                continue
        return False

    @staticmethod
    async def _overlay_still_visible(el) -> bool:
        """Visibility check that treats a detached/removed element as gone."""
        try:
            return await el.is_visible()
        except Exception:
            return False

    async def _is_dismiss_only_overlay(self, page: Page) -> bool:
        """Detect overlays that should be closed rather than explored (global
        search drawers / typeaheads that trap pointer events)."""
        for selector in DRAWER_OVERLAY_SELECTORS:
            try:
                for el in await page.query_selector_all(selector):
                    if await el.is_visible():
                        return True
            except Exception:
                continue
        return False

    async def _dismiss_blocking_drawer(self, page: Page) -> None:
        """Close a drawer/typeahead overlay that exposes no Close control and
        traps pointer events. Blur the focused field so Escape reaches the
        dialog, then click any backdrop near a corner as a fallback (avoiding a
        centred panel)."""
        try:
            await page.evaluate('() => document.activeElement && document.activeElement.blur()')
        except Exception:
            pass
        try:
            await page.keyboard.press('Escape')
            await page.wait_for_timeout(300)
        except Exception:
            pass
        for selector in BACKDROP_SELECTORS:
            try:
                for el in await page.query_selector_all(selector):
                    if not await el.is_visible():
                        continue
                    box = await el.bounding_box()
                    if box:
                        await page.mouse.click(box['x'] + 5, box['y'] + 5)
                        await page.wait_for_timeout(300)
            except Exception:
                continue

    async def handle(self, page: Page) -> None:
        """Attempt to interact with and dismiss any blocking modal."""
        logger.info("Handling overlay: attempting affirmative actions first...")

        # Handle a global search drawer / typeahead before the calendar heuristic:
        # it's a hard blocker with no Close control, and the calendar check can
        # false-match a dialog that merely contains a grid.
        if await self._is_dismiss_only_overlay(page):
            logger.info("Search/drawer overlay detected; closing it.")
            await self._dismiss_blocking_drawer(page)
            return

        if await self.dismiss_calendar_overlay(page):
            logger.info("Dismissed calendar overlay")
            return

        try:
            modal_container = await self._find_modal_container(page)
            action_taken = False

            if modal_container:
                logger.info("Modal container identified. Filling forms and searching for interactive elements...")
                await self.form_filler.fill(page, root=modal_container)
                action_taken = await self._click_interactive_in_modal(modal_container, page)
            else:
                logger.info("Could not explicitly identify modal container. Falling back to targeted selectors.")
                action_taken = await self._click_affirmative_fallback(page)

            if action_taken:
                await page.wait_for_timeout(1000)

            # A custom dropdown (e.g. select2) opened while filling/clicking leaves
            # a full-screen mask that blocks the dialog's own Close button. Remove
            # it so the dismiss selectors and Escape below can actually close the
            # modal instead of every later click being intercepted.
            await neutralize_dropdown_masks(page)

            await self._run_dismiss_selectors(page)
            await page.keyboard.press('Escape')
            await page.wait_for_timeout(500)

        except Exception as e:
            logger.error("Error while trying to handle overlay: %s", e)

    async def _find_modal_container(self, page: Page):
        for selector in MODAL_CONTAINER_SELECTORS:
            try:
                elements = await page.query_selector_all(selector)
                for el in elements:
                    if await el.is_visible():
                        return el
            except Exception:
                continue
        return None

    async def _click_interactive_in_modal(self, modal_container, page: Page) -> bool:
        action_taken = False
        try:
            interactive_elements = await modal_container.query_selector_all(INTERACTIVE_SELECTORS)
            for el in interactive_elements:
                if not await el.is_visible():
                    continue
                if await self._opens_blocking_dropdown(el):
                    logger.debug("Skipping custom-dropdown trigger (would open a blocking mask)")
                    continue
                if await is_destructive_action(el, exclude_patterns=self.exclude_patterns):
                    continue

                combined_text = ''
                try:
                    combined_text = (await el.text_content() or '').strip()
                except Exception:
                    pass

                logger.debug("Clicking actionable element in modal: '%s'", combined_text[:30])
                try:
                    await el.click(timeout=2000)
                    await page.wait_for_timeout(1000)
                    action_taken = True
                except Exception as click_err:
                    logger.warning("Could not click modal element: %s", click_err)
        except Exception as e:
            logger.error("Error exploring modal elements: %s", e)
        return action_taken

    @staticmethod
    async def _opens_blocking_dropdown(el) -> bool:
        """Detect custom-dropdown triggers (e.g. select2's choice anchor) whose
        click opens a full-screen mask that traps every subsequent click and
        can't be reliably closed, stalling the whole page. Better to leave them
        unclicked than to strand the crawler behind their mask."""
        try:
            return await el.evaluate('''el => {
                if (el.closest('.select2-container, .select2-choice, [class*="select2"]')) return true;
                const cls = (typeof el.className === 'string' ? el.className : '').toLowerCase();
                return cls.includes('select2');
            }''')
        except Exception:
            return False

    async def _click_affirmative_fallback(self, page: Page) -> bool:
        action_taken = False
        for selector in AFFIRMATIVE_ACTION_SELECTORS:
            try:
                elements = await page.query_selector_all(selector)
                for el in elements:
                    if await el.is_visible():
                        logger.debug("Clicking affirmative action as fallback: %s", selector)
                        await el.click(timeout=2000)
                        await page.wait_for_timeout(1000)
                        action_taken = True
            except Exception:
                continue
        return action_taken

    async def _run_dismiss_selectors(self, page: Page) -> None:
        for selector in DISMISS_SELECTORS:
            try:
                elements = await page.query_selector_all(selector)
                for el in elements:
                    if await el.is_visible():
                        logger.debug("Clicking dismiss action in overlay: %s", selector)
                        await el.click(timeout=2000)
                        await page.wait_for_timeout(500)
            except Exception:
                continue
