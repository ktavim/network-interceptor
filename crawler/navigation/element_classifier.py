"""Classify interactive elements: destructive actions, date pickers, clickables."""
import logging
from typing import Iterable, List

from playwright.async_api import Page, Locator

from .selectors import (
    CLICKABLE_SELECTORS,
    DATE_INPUT_TYPES,
    DATE_PICKER_PATTERNS,
    DESTRUCTIVE_PATTERNS,
    DESTRUCTIVE_TEXT_EXACT,
)

logger = logging.getLogger(__name__)


async def is_destructive_action(element, text: str = "", exclude_patterns: Iterable[str] = ()) -> bool:
    """Check if element action is destructive or dismissive (logout, delete, close, etc.)."""
    if not text:
        try:
            text = await element.text_content() or ""
        except Exception:
            text = ""

    text_lower = text.strip().lower()

    href = ""
    classes = ""
    element_id = ""
    aria_label = ""
    try:
        href = (await element.get_attribute('href') or "").lower()
    except Exception:
        pass
    try:
        classes = (await element.get_attribute('class') or "").lower()
        element_id = (await element.get_attribute('id') or "").lower()
    except Exception:
        pass
    try:
        aria_label = (await element.get_attribute('aria-label') or "").lower()
    except Exception:
        pass

    searchable = [text_lower, href, classes, element_id, aria_label]

    for pattern in exclude_patterns:
        pattern_lower = pattern.lower()
        if any(pattern_lower in s for s in searchable):
            return True

    for pattern in DESTRUCTIVE_PATTERNS:
        if any(pattern in s for s in searchable):
            return True

    if text_lower in DESTRUCTIVE_TEXT_EXACT:
        return True

    return False


async def is_date_picker_element(element) -> bool:
    """Check if element is a date picker trigger that should be skipped."""
    try:
        input_type = (await element.get_attribute('type') or "").lower()
        if input_type in DATE_INPUT_TYPES:
            return True
    except Exception:
        pass

    attrs = []
    for attr_name in ('class', 'id', 'aria-label', 'name'):
        try:
            attrs.append((await element.get_attribute(attr_name) or "").lower())
        except Exception:
            pass

    for attr_val in attrs:
        for pattern in DATE_PICKER_PATTERNS:
            if pattern in attr_val:
                return True

    try:
        is_date_related = await element.evaluate('''(el) => {
            const pickerAncestor = el.closest(
                '[class*="datepicker"], [class*="date-picker"], [class*="calendar"], '
              + '[class*="flatpickr"], [class*="mat-datepicker"], [class*="ant-picker"], '
              + '[class*="react-datepicker"]'
            );
            if (pickerAncestor) return true;
            const parent = el.parentElement;
            if (parent) {
                const dateInput = parent.querySelector(
                    'input[type="date"], input[type="datetime-local"], '
                  + 'input[type="time"], input[type="month"], input[type="week"]'
                );
                if (dateInput) return true;
            }
            return false;
        }''')
        if is_date_related:
            return True
    except Exception:
        pass

    return False


async def neutralize_dropdown_masks(page: Page) -> int:
    """Remove leftover custom-dropdown masks that trap pointer events.

    Widgets like select2 open a full-screen ``#select2-drop-mask`` to capture the
    next outside-click; once open it intercepts *every* click on the page —
    including a modal's own Close button — until dismissed. Clicking the mask is
    fragile (it depends on stacking order and the widget's own handler firing and,
    for a modal backdrop, would wrongly close the surrounding modal), so we remove
    the mask node outright and tidy the open-dropdown state. Returns the number of
    mask nodes removed.
    """
    try:
        return await page.evaluate('''() => {
            let removed = 0;
            document.querySelectorAll('#select2-drop-mask, .select2-drop-mask').forEach(e => {
                e.remove();
                removed++;
            });
            document.querySelectorAll('.select2-drop, .select2-drop-active').forEach(e => {
                e.style.display = 'none';
                e.classList.remove('select2-drop-active');
            });
            document.querySelectorAll('.select2-dropdown-open, .select2-container-active').forEach(e => {
                e.classList.remove('select2-dropdown-open', 'select2-container-active');
            });
            return removed;
        }''')
    except Exception:
        return 0


async def get_clickable_elements(
    page: Page,
    max_clicks: int,
    exclude_patterns: Iterable[str] = (),
) -> List[Locator]:
    """Get all clickable elements on current page, filtered and deduplicated."""
    all_elements: List[Locator] = []
    seen_elements = set()

    for selector in CLICKABLE_SELECTORS:
        try:
            page_elements = await page.query_selector_all(selector)
            for idx, elem in enumerate(page_elements):
                try:
                    locator = page.locator(selector).nth(idx)

                    try:
                        elem_html = await elem.evaluate('el => el.outerHTML')
                        if elem_html in seen_elements:
                            continue
                        seen_elements.add(elem_html)
                    except Exception:
                        pass

                    try:
                        if await locator.is_visible():
                            is_clickable = await elem.evaluate('''el => {
                                if (el.disabled) return false;
                                if (el.getAttribute('aria-disabled') === 'true') return false;
                                // Skip-to-content accessibility links (e.g. Atlassian AUI's
                                // .aui-skip-link) are off-screen anchors that only trap the
                                // click timeout.
                                const cls = (typeof el.className === 'string' ? el.className : '').toLowerCase();
                                if (cls.includes('skip-link')) return false;
                                const style = window.getComputedStyle(el);
                                if (style.pointerEvents === 'none') return false;
                                const rect = el.getBoundingClientRect();
                                if (rect.width <= 0 || rect.height <= 0) return false;
                                // Reject only elements off the inline-start/top: at collection
                                // time the page sits at the scroll origin, so they can't be
                                // scrolled into reach (the off-screen skip-link idiom). Elements
                                // past the inline-end/bottom are normal content that
                                // scroll_into_view reaches at click time, so they stay.
                                // Inline-start is the left edge in LTR but the right edge in RTL,
                                // so the unreachable horizontal side flips with writing direction.
                                const docDir = window.getComputedStyle(document.documentElement).direction;
                                const offInlineStart = docDir === 'rtl'
                                    ? rect.left >= window.innerWidth
                                    : rect.right <= 0;
                                if (offInlineStart) return false;
                                if (rect.bottom <= 0) return false;
                                return true;
                            }''')

                            if is_clickable and not await is_destructive_action(locator, exclude_patterns=exclude_patterns):
                                if await is_date_picker_element(elem):
                                    logger.debug("Skipping date picker element")
                                    continue
                                all_elements.append(locator)
                                if len(all_elements) >= max_clicks:
                                    return all_elements
                    except Exception:
                        continue
                except Exception:
                    continue
        except Exception:
            continue

    return all_elements[:max_clicks]
