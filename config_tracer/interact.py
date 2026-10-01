"""Time-budgeted, safe page interactions to surface lazy-loaded XHRs."""

import logging
import re
import time

from playwright.async_api import Page

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Interaction simulation
# ---------------------------------------------------------------------------

# Text/attribute patterns that mark a control as risky to click during crawling
_DANGER_TEXT_RE = re.compile(r"sign\s*out|log\s*out|delete|remove|destroy", re.IGNORECASE)


async def _safe_wait_idle(page: Page, timeout_ms: int = 1000) -> None:
    try:
        await page.wait_for_load_state("networkidle", timeout=timeout_ms)
    except Exception:
        pass


async def _is_safe_to_click(el) -> bool:
    """Heuristic: skip submit buttons, danger text, cross-origin links, form descendants."""
    try:
        text = (await el.inner_text()).strip() if await el.is_visible() else ""
    except Exception:
        return False
    if text and _DANGER_TEXT_RE.search(text):
        return False
    try:
        in_form = await el.evaluate("el => !!el.closest('form')")
        if in_form:
            return False
    except Exception:
        return False
    try:
        type_attr = (await el.get_attribute("type")) or ""
        if type_attr.lower() == "submit":
            return False
    except Exception:
        pass
    try:
        testid = (await el.get_attribute("data-testid")) or ""
        if "logout" in testid.lower() or "signout" in testid.lower():
            return False
    except Exception:
        pass
    return True


async def _run_interactions(page: Page, budget_ms: int) -> None:
    """Generic, time-budgeted interactions to surface lazy/click-triggered XHRs."""
    deadline = time.monotonic() + budget_ms / 1000.0

    def time_left() -> bool:
        return time.monotonic() < deadline

    # Step 1: incremental scroll
    if time_left():
        try:
            for _ in range(4):
                if not time_left():
                    break
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                await page.wait_for_timeout(250)
            await _safe_wait_idle(page)
        except Exception as e:
            log.warning("scroll failed: %s", e)

    # Step 2: hover top-level nav (route prefetch)
    if time_left():
        try:
            nav_locator = page.locator("nav a, header a, [role=menuitem]")
            count = min(await nav_locator.count(), 6)
            for i in range(count):
                if not time_left():
                    break
                try:
                    await nav_locator.nth(i).hover(timeout=500)
                except Exception:
                    pass
            await _safe_wait_idle(page)
        except Exception as e:
            log.warning("hover failed: %s", e)

    # Step 3: click visible safe controls (buttons, tabs, disclosures)
    if time_left():
        try:
            click_locator = page.locator(
                "button:not([type=submit]), [role=tab], [aria-expanded=false]"
            )
            count = min(await click_locator.count(), 8)
            for i in range(count):
                if not time_left():
                    break
                el = click_locator.nth(i)
                try:
                    if not await el.is_visible():
                        continue
                    if not await _is_safe_to_click(el):
                        continue
                    await el.click(timeout=750, trial=True)
                    await el.click(timeout=1500, no_wait_after=True)
                    await _safe_wait_idle(page, timeout_ms=750)
                    try:
                        await page.keyboard.press("Escape")
                    except Exception:
                        pass
                except Exception:
                    continue
        except Exception as e:
            log.warning("click pass failed: %s", e)
