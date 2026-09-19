"""Tests for crawler.navigation.element_classifier."""
import pytest
from unittest.mock import AsyncMock, MagicMock

from crawler.navigation.element_classifier import (
    is_destructive_action,
    is_date_picker_element,
    get_clickable_elements,
    neutralize_dropdown_masks,
)


class TestNeutralizeDropdownMasks:
    async def test_returns_removed_count(self, mock_page):
        page = mock_page()
        page.evaluate = AsyncMock(return_value=2)
        assert await neutralize_dropdown_masks(page) == 2

    async def test_zero_when_no_mask(self, mock_page):
        page = mock_page()
        page.evaluate = AsyncMock(return_value=0)
        assert await neutralize_dropdown_masks(page) == 0

    async def test_swallows_exception(self, mock_page):
        page = mock_page()
        page.evaluate = AsyncMock(side_effect=Exception("execution context destroyed"))
        assert await neutralize_dropdown_masks(page) == 0


class TestIsDestructiveAction:
    async def test_logout_text(self, mock_element):
        assert await is_destructive_action(mock_element(text="Logout")) is True

    async def test_delete_href(self, mock_element):
        assert await is_destructive_action(
            mock_element(text="Remove", href="/api/delete/1")
        ) is True

    async def test_close_text(self, mock_element):
        assert await is_destructive_action(mock_element(text="Close")) is True

    async def test_cancel_aria(self, mock_element):
        assert await is_destructive_action(mock_element(aria_label="cancel")) is True

    async def test_destroy(self, mock_element):
        assert await is_destructive_action(mock_element(text="Destroy record")) is True

    async def test_clear(self, mock_element):
        assert await is_destructive_action(mock_element(text="Clear all")) is True

    async def test_no_thanks(self, mock_element):
        assert await is_destructive_action(mock_element(text="No thanks")) is True

    async def test_x_exact_match(self, mock_element):
        assert await is_destructive_action(mock_element(text="x")) is True

    async def test_case_insensitive(self, mock_element):
        assert await is_destructive_action(mock_element(text="LOGOUT")) is True

    async def test_pattern_in_href(self, mock_element):
        assert await is_destructive_action(
            mock_element(text="Go", href="/user/logout")
        ) is True

    async def test_pattern_in_class(self, mock_element):
        assert await is_destructive_action(
            mock_element(text="Click", classes="btn-cancel")
        ) is True

    async def test_pattern_in_id(self, mock_element):
        assert await is_destructive_action(mock_element(element_id="btn-logout")) is True

    async def test_not_destructive_submit(self, mock_element):
        assert await is_destructive_action(mock_element(text="Submit")) is False

    async def test_not_destructive_empty(self, mock_element):
        assert await is_destructive_action(mock_element()) is False

    async def test_custom_exclude_pattern(self, mock_element):
        assert await is_destructive_action(
            mock_element(text="Settings"), exclude_patterns=["settings"]
        ) is True

    async def test_custom_case_insensitive(self, mock_element):
        assert await is_destructive_action(
            mock_element(text="admin panel"), exclude_patterns=["Admin"]
        ) is True

    async def test_explicit_text_overrides(self, mock_element):
        assert await is_destructive_action(
            mock_element(text="Submit"), text="logout"
        ) is True

    async def test_exception_on_text_content(self):
        el = AsyncMock()
        el.text_content = AsyncMock(side_effect=Exception("detached"))
        el.get_attribute = AsyncMock(return_value=None)
        assert await is_destructive_action(el) is False

    async def test_exception_on_get_attribute(self):
        el = AsyncMock()
        el.text_content = AsyncMock(return_value="Safe")
        el.get_attribute = AsyncMock(side_effect=Exception("detached"))
        assert await is_destructive_action(el) is False


class TestIsDatePickerElement:
    @pytest.mark.parametrize("itype", ["date", "datetime-local", "time", "month", "week"])
    async def test_date_input_types(self, mock_element, itype):
        assert await is_date_picker_element(mock_element(input_type=itype)) is True

    async def test_text_input_not_date(self, mock_element):
        assert await is_date_picker_element(mock_element(input_type="text")) is False

    @pytest.mark.parametrize("cls", [
        "my-datepicker-trigger", "calendar-button", "flatpickr-input",
        "react-datepicker__input", "MyDatePicker", "ant-picker-input",
        "mat-datepicker-toggle",
    ])
    async def test_datepicker_classes(self, mock_element, cls):
        assert await is_date_picker_element(mock_element(classes=cls)) is True

    async def test_calendar_aria(self, mock_element):
        assert await is_date_picker_element(mock_element(aria_label="Open calendar")) is True

    async def test_datepicker_id(self, mock_element):
        assert await is_date_picker_element(mock_element(element_id="booking-datepicker")) is True

    async def test_datepicker_name(self, mock_element):
        assert await is_date_picker_element(mock_element(name="datepicker-start")) is True

    async def test_normal_button(self, mock_element):
        assert await is_date_picker_element(mock_element(text="Submit", classes="btn")) is False

    async def test_ancestor_evaluate(self, mock_element):
        assert await is_date_picker_element(mock_element(evaluate_result=True)) is True

    async def test_not_ancestor(self, mock_element):
        assert await is_date_picker_element(mock_element(evaluate_result=False)) is False

    async def test_exception_on_evaluate(self, mock_element):
        el = mock_element(classes="normal")
        el.evaluate = AsyncMock(side_effect=Exception("x"))
        assert await is_date_picker_element(el) is False


class TestGetClickableElements:
    async def test_returns_empty_when_no_elements(self):
        page = MagicMock()
        page.query_selector_all = AsyncMock(return_value=[])
        page.locator = MagicMock()
        result = await get_clickable_elements(page, max_clicks=10)
        assert result == []

    @staticmethod
    def _make_enabled_elem(html: str):
        """Elem whose .evaluate returns outerHTML → is-enabled(True)
        and whose get_attribute returns None (not a date picker)."""
        e = AsyncMock()
        e.evaluate = AsyncMock(side_effect=[html, True, False])
        e.get_attribute = AsyncMock(return_value=None)
        return e

    @staticmethod
    def _make_loc(text="go"):
        loc = AsyncMock()
        loc.is_visible = AsyncMock(return_value=True)
        loc.text_content = AsyncMock(return_value=text)
        loc.get_attribute = AsyncMock(return_value=None)
        return loc

    async def test_collects_enabled_visible_element(self):
        from crawler.navigation import element_classifier as ec
        page = MagicMock()
        elem = self._make_enabled_elem("<button>OK</button>")
        loc = self._make_loc("OK")

        page.query_selector_all = AsyncMock(
            side_effect=lambda sel: [elem] if sel == "button" else []
        )
        page.locator = MagicMock(
            side_effect=lambda sel: MagicMock(nth=MagicMock(return_value=loc))
        )

        original = ec.CLICKABLE_SELECTORS
        ec.CLICKABLE_SELECTORS = ["button"]
        try:
            result = await get_clickable_elements(page, max_clicks=10)
        finally:
            ec.CLICKABLE_SELECTORS = original
        assert len(result) == 1

    async def test_respects_max_clicks(self):
        from crawler.navigation import element_classifier as ec
        page = MagicMock()
        elems = [self._make_enabled_elem(f"<b>{i}</b>") for i in range(5)]
        locators = [self._make_loc() for _ in range(5)]

        page.query_selector_all = AsyncMock(
            side_effect=lambda sel: elems if sel == "button" else []
        )
        page.locator = MagicMock(
            side_effect=lambda sel: MagicMock(nth=MagicMock(side_effect=lambda i: locators[i]))
        )

        original = ec.CLICKABLE_SELECTORS
        ec.CLICKABLE_SELECTORS = ["button"]
        try:
            result = await get_clickable_elements(page, max_clicks=2)
        finally:
            ec.CLICKABLE_SELECTORS = original

        assert len(result) == 2
