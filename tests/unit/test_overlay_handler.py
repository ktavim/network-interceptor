"""Tests for crawler.navigation.overlay_handler.OverlayHandler."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from crawler.navigation.overlay_handler import OverlayHandler
from crawler.navigation.form_filler import FormFiller


@pytest.fixture
def overlay(make_config):
    ff = FormFiller(make_config())
    return OverlayHandler(ff, exclude_patterns=["logout"])


class TestIsCalendarOverlay:
    async def test_positive(self, overlay):
        container = MagicMock()
        container.evaluate = AsyncMock(return_value=True)
        assert await overlay.is_calendar_overlay(container) is True

    async def test_negative(self, overlay):
        container = MagicMock()
        container.evaluate = AsyncMock(return_value=False)
        assert await overlay.is_calendar_overlay(container) is False

    async def test_exception_returns_false(self, overlay):
        container = MagicMock()
        container.evaluate = AsyncMock(side_effect=Exception("detached"))
        assert await overlay.is_calendar_overlay(container) is False


class TestDismissCalendarOverlay:
    async def test_dismisses_when_calendar(self, overlay, mock_page):
        page = mock_page()
        cal = AsyncMock()
        # Detected as visible, then gone once Escape is pressed.
        cal.is_visible = AsyncMock(side_effect=[True, False])
        cal.evaluate = AsyncMock(return_value=True)

        call_count = {"n": 0}

        async def qs(sel):
            call_count["n"] += 1
            return [cal] if call_count["n"] == 1 else []
        page.query_selector_all = AsyncMock(side_effect=qs)

        result = await overlay.dismiss_calendar_overlay(page)
        assert result is True
        page.keyboard.press.assert_called_with("Escape")

    async def test_returns_false_when_overlay_persists(self, overlay, mock_page):
        """A matched overlay that survives Escape + click must report False so
        handle() falls through to the real blocking modal instead of stopping."""
        page = mock_page()
        cal = AsyncMock()
        cal.is_visible = AsyncMock(return_value=True)  # never goes away
        cal.evaluate = AsyncMock(return_value=True)
        page.query_selector_all = AsyncMock(return_value=[cal])

        result = await overlay.dismiss_calendar_overlay(page)
        assert result is False
        page.mouse.click.assert_any_call(0, 0)  # tried the click-outside fallback

    async def test_returns_false_when_no_calendar(self, overlay, mock_page):
        page = mock_page()
        page.query_selector_all = AsyncMock(return_value=[])
        assert await overlay.dismiss_calendar_overlay(page) is False

    async def test_skips_invisible(self, overlay, mock_page):
        page = mock_page()
        inv = AsyncMock()
        inv.is_visible = AsyncMock(return_value=False)
        page.query_selector_all = AsyncMock(return_value=[inv])
        assert await overlay.dismiss_calendar_overlay(page) is False


class TestHandle:
    async def test_calendar_short_circuits(self, overlay, mock_page):
        page = mock_page()
        overlay.dismiss_calendar_overlay = AsyncMock(return_value=True)
        overlay._find_modal_container = AsyncMock()
        await overlay.handle(page)
        overlay._find_modal_container.assert_not_called()

    async def test_drawer_overlay_closed_before_calendar(self, overlay, mock_page):
        """A search/drawer overlay is closed first and must not fall through to
        the calendar heuristic or general modal handling."""
        page = mock_page()
        overlay._is_dismiss_only_overlay = AsyncMock(return_value=True)
        overlay._dismiss_blocking_drawer = AsyncMock()
        overlay.dismiss_calendar_overlay = AsyncMock(return_value=True)
        overlay._find_modal_container = AsyncMock()

        await overlay.handle(page)

        overlay._dismiss_blocking_drawer.assert_called_once()
        overlay.dismiss_calendar_overlay.assert_not_called()
        overlay._find_modal_container.assert_not_called()

    async def test_fills_forms_and_clicks_in_modal(self, overlay, mock_page):
        page = mock_page()
        overlay.dismiss_calendar_overlay = AsyncMock(return_value=False)
        modal = MagicMock()
        overlay._find_modal_container = AsyncMock(return_value=modal)
        overlay.form_filler.fill = AsyncMock()
        overlay._click_interactive_in_modal = AsyncMock(return_value=True)
        overlay._run_dismiss_selectors = AsyncMock()

        await overlay.handle(page)

        overlay.form_filler.fill.assert_called_once()
        overlay._click_interactive_in_modal.assert_called_once_with(modal, page)
        overlay._run_dismiss_selectors.assert_called_once()

    async def test_fallback_when_no_modal(self, overlay, mock_page):
        page = mock_page()
        overlay.dismiss_calendar_overlay = AsyncMock(return_value=False)
        overlay._find_modal_container = AsyncMock(return_value=None)
        overlay._click_affirmative_fallback = AsyncMock(return_value=False)
        overlay._run_dismiss_selectors = AsyncMock()

        await overlay.handle(page)

        overlay._click_affirmative_fallback.assert_called_once()
        overlay._run_dismiss_selectors.assert_called_once()


class TestFindModalContainer:
    async def test_returns_first_visible(self, overlay, mock_page):
        page = mock_page()
        hidden = AsyncMock()
        hidden.is_visible = AsyncMock(return_value=False)
        visible = AsyncMock()
        visible.is_visible = AsyncMock(return_value=True)
        page.query_selector_all = AsyncMock(return_value=[hidden, visible])
        result = await overlay._find_modal_container(page)
        assert result is visible

    async def test_returns_none_when_none_visible(self, overlay, mock_page):
        page = mock_page()
        page.query_selector_all = AsyncMock(return_value=[])
        assert await overlay._find_modal_container(page) is None


class TestOpensBlockingDropdown:
    async def test_true_for_select2(self, overlay):
        el = AsyncMock()
        el.evaluate = AsyncMock(return_value=True)
        assert await overlay._opens_blocking_dropdown(el) is True

    async def test_false_for_plain(self, overlay):
        el = AsyncMock()
        el.evaluate = AsyncMock(return_value=False)
        assert await overlay._opens_blocking_dropdown(el) is False

    async def test_exception_returns_false(self, overlay):
        el = AsyncMock()
        el.evaluate = AsyncMock(side_effect=Exception("detached"))
        assert await overlay._opens_blocking_dropdown(el) is False


class TestNeutralizeInHandle:
    async def test_neutralizes_masks_before_dismiss(self, overlay, mock_page):
        """handle() must strip a leftover dropdown mask so the dismiss selectors
        can actually reach the modal's Close button."""
        page = mock_page()
        overlay._is_dismiss_only_overlay = AsyncMock(return_value=False)
        overlay.dismiss_calendar_overlay = AsyncMock(return_value=False)
        overlay._find_modal_container = AsyncMock(return_value=None)
        overlay._click_affirmative_fallback = AsyncMock(return_value=False)
        overlay._run_dismiss_selectors = AsyncMock()

        with patch(
            "crawler.navigation.overlay_handler.neutralize_dropdown_masks",
            AsyncMock(return_value=1),
        ) as neut:
            await overlay.handle(page)

        neut.assert_called_once()
        overlay._run_dismiss_selectors.assert_called_once()


class TestClickInteractiveInModal:
    async def test_skips_select2_trigger(self, overlay, mock_page, mock_element):
        page = mock_page()
        modal = MagicMock()
        trigger = mock_element(text="Choose a space")
        trigger.is_visible = AsyncMock(return_value=True)
        trigger.click = AsyncMock()
        modal.query_selector_all = AsyncMock(return_value=[trigger])
        overlay._opens_blocking_dropdown = AsyncMock(return_value=True)

        result = await overlay._click_interactive_in_modal(modal, page)
        assert result is False
        trigger.click.assert_not_called()

    async def test_skips_destructive(self, overlay, mock_page, mock_element):
        page = mock_page()
        modal = MagicMock()
        destructive = mock_element(text="Logout")
        destructive.is_visible = AsyncMock(return_value=True)
        destructive.click = AsyncMock()
        modal.query_selector_all = AsyncMock(return_value=[destructive])
        result = await overlay._click_interactive_in_modal(modal, page)
        assert result is False
        destructive.click.assert_not_called()

    async def test_clicks_non_destructive(self, overlay, mock_page, mock_element):
        page = mock_page()
        modal = MagicMock()
        el = mock_element(text="Continue")
        el.is_visible = AsyncMock(return_value=True)
        el.click = AsyncMock()
        modal.query_selector_all = AsyncMock(return_value=[el])
        result = await overlay._click_interactive_in_modal(modal, page)
        assert result is True
        el.click.assert_called_once()
