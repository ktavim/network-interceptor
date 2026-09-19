"""Tests for crawler.navigation.form_filler.FormFiller (pure logic helpers)."""
import pytest
from unittest.mock import AsyncMock

from crawler.navigation.form_filler import FormFiller


@pytest.fixture
def filler(make_config):
    return FormFiller(make_config())


class TestPadValue:
    def test_already_long_enough(self):
        assert FormFiller._pad_value("long enough", 5) == "long enough"

    def test_exact_length(self):
        assert FormFiller._pad_value("12345", 5) == "12345"

    def test_pad_short_text(self):
        r = FormFiller._pad_value("hi", 8)
        assert r.startswith("hi")
        assert len(r) == 8

    def test_pad_email_preserves_domain(self):
        r = FormFiller._pad_value("a@b.com", 15)
        assert r.endswith("@b.com")
        assert len(r) == 15

    def test_pad_email_fills_local_part(self):
        r = FormFiller._pad_value("t@e.com", 20)
        assert "@e.com" in r
        assert len(r) == 20

    def test_min_length_zero(self):
        assert FormFiller._pad_value("abc", 0) == "abc"

    def test_single_char_to_long(self):
        r = FormFiller._pad_value("a", 20)
        assert r[0] == "a"
        assert r[1:] == "x" * 19


class TestGetMinimumLength:
    async def test_minlength_attr(self, filler, mock_element):
        el = mock_element(minlength="12")
        assert await filler._get_minimum_length(el) == 12

    async def test_minlength_non_numeric(self, filler, mock_element):
        el = mock_element(minlength="abc")
        assert await filler._get_minimum_length(el) == 0

    async def test_pattern_with_min(self, filler, mock_element):
        el = mock_element(pattern=r".{8,20}")
        assert await filler._get_minimum_length(el) == 8

    async def test_no_constraints(self, filler, mock_element):
        el = mock_element()
        assert await filler._get_minimum_length(el) == 0

    async def test_required_password_defaults_to_8(self, filler, mock_element):
        el = mock_element(input_type="password", required="")
        assert await filler._get_minimum_length(el) == 8

    async def test_exception_returns_zero(self, filler):
        el = AsyncMock()
        el.get_attribute = AsyncMock(side_effect=Exception("detached"))
        assert await filler._get_minimum_length(el) == 0


class TestDetermineFillValue:
    async def test_email_type(self, filler, mock_element):
        assert await filler._determine_fill_value(mock_element(input_type="email")) == "test@example.com"

    async def test_password_type(self, filler, mock_element):
        assert await filler._determine_fill_value(mock_element(input_type="password")) == "Password123!"

    async def test_tel_type(self, filler, mock_element):
        assert await filler._determine_fill_value(mock_element(input_type="tel")) == "555-012345"

    async def test_number_type(self, filler, mock_element):
        assert await filler._determine_fill_value(mock_element(input_type="number")) == "1"

    async def test_url_type(self, filler, mock_element):
        assert await filler._determine_fill_value(mock_element(input_type="url")) == "https://example.com"

    async def test_date_type(self, filler, mock_element):
        assert await filler._determine_fill_value(mock_element(input_type="date")) == "2024-01-01"

    async def test_email_by_name(self, filler, mock_element):
        el = mock_element(input_type="text", name="user_email")
        assert await filler._determine_fill_value(el) == "test@example.com"

    async def test_phone_by_name(self, filler, mock_element):
        el = mock_element(input_type="text", name="phone_number")
        assert await filler._determine_fill_value(el) == "555-012345"

    async def test_password_by_id(self, filler, mock_element):
        el = mock_element(input_type="text", element_id="new_password")
        assert await filler._determine_fill_value(el) == "Password123!"

    async def test_default_for_plain_text(self, filler, mock_element):
        assert await filler._determine_fill_value(mock_element(input_type="text", name="first")) == "Test-value-for-filling"

    async def test_config_default_overrides(self, make_config, mock_element):
        from config_loader import FormConfig
        cfg = make_config(form_filling=FormConfig(defaults={"#email": "custom@x.com"}))
        filler = FormFiller(cfg)
        el = mock_element(input_type="email", element_id="email")
        el.evaluate = AsyncMock(return_value=True)
        assert await filler._determine_fill_value(el) == "custom@x.com"


class TestGetElementLabel:
    async def test_prefers_textcontent(self, filler, mock_element):
        el = mock_element(aria_label="aria", placeholder="ph")
        el.evaluate = AsyncMock(return_value="Hello")
        label = await filler._get_element_label(el)
        assert "Hello" in label

    async def test_falls_back_to_aria(self, filler, mock_element):
        el = mock_element(aria_label="aria_label_here", placeholder="ph")
        el.evaluate = AsyncMock(return_value="")
        label = await filler._get_element_label(el)
        assert "aria_label_here" in label

    async def test_falls_back_to_placeholder(self, filler, mock_element):
        el = mock_element(placeholder="enter name", name="n")
        el.evaluate = AsyncMock(return_value="")
        label = await filler._get_element_label(el)
        assert "enter name" in label

    async def test_falls_back_to_name(self, filler, mock_element):
        el = mock_element(name="username", element_id="u")
        el.evaluate = AsyncMock(return_value="")
        label = await filler._get_element_label(el)
        assert "username" in label

    async def test_falls_back_to_id(self, filler, mock_element):
        el = mock_element(element_id="my-id")
        el.evaluate = AsyncMock(return_value="")
        label = await filler._get_element_label(el)
        assert "my-id" in label

    async def test_returns_empty_when_no_info(self, filler, mock_element):
        el = mock_element()
        el.evaluate = AsyncMock(return_value="")
        assert await filler._get_element_label(el) == ""

    async def test_truncates_to_30(self, filler, mock_element):
        el = mock_element()
        el.evaluate = AsyncMock(return_value="a" * 100)
        label = await filler._get_element_label(el)
        assert "a" * 30 in label
        assert "a" * 31 not in label


class TestDismissDropdownMask:
    async def test_removes_mask_returns_true(self, filler, mock_page):
        page = mock_page()
        page.evaluate = AsyncMock(return_value=1)  # one mask node removed
        assert await filler._dismiss_dropdown_mask(page) is True
        # DOM removal, not a coordinate click that could hit the wrong element.
        page.mouse.click.assert_not_called()
        # Never presses Escape (would bubble up and close the surrounding modal).
        page.keyboard.press.assert_not_called()

    async def test_no_mask_returns_false(self, filler, mock_page):
        page = mock_page()
        page.evaluate = AsyncMock(return_value=0)
        assert await filler._dismiss_dropdown_mask(page) is False

    async def test_evaluate_exception_returns_false(self, filler, mock_page):
        page = mock_page()
        page.evaluate = AsyncMock(side_effect=Exception("execution context destroyed"))
        assert await filler._dismiss_dropdown_mask(page) is False


class TestTryClickDropdown:
    async def test_recovers_from_intercepted_click(self, filler, mock_page):
        """First click is blocked by a leftover mask; after dismissing it the
        retry succeeds and an option is selected."""
        page = mock_page()
        input_el = AsyncMock()
        input_el.click = AsyncMock(side_effect=[
            Exception("Timeout 2000ms exceeded ... intercepts pointer events"),
            None,
        ])
        filler._dismiss_dropdown_mask = AsyncMock(return_value=True)
        filler._try_dropdown_options = AsyncMock(return_value=True)

        assert await filler._try_click_dropdown(input_el, page) is True
        assert input_el.click.call_count == 2
        filler._dismiss_dropdown_mask.assert_called_once()

    async def test_gives_up_when_mask_cannot_be_dismissed(self, filler, mock_page):
        page = mock_page()
        input_el = AsyncMock()
        input_el.click = AsyncMock(side_effect=Exception("... intercepts pointer events"))
        filler._dismiss_dropdown_mask = AsyncMock(return_value=False)
        filler._try_dropdown_options = AsyncMock(return_value=True)

        assert await filler._try_click_dropdown(input_el, page) is False
        input_el.click.assert_called_once()  # no retry without a dismissable mask
        filler._try_dropdown_options.assert_not_called()

    async def test_non_intercept_error_does_not_dismiss(self, filler, mock_page):
        page = mock_page()
        input_el = AsyncMock()
        input_el.click = AsyncMock(side_effect=Exception("element detached"))
        filler._dismiss_dropdown_mask = AsyncMock(return_value=False)

        assert await filler._try_click_dropdown(input_el, page) is False
        filler._dismiss_dropdown_mask.assert_not_called()

    async def test_closes_dropdown_left_open_with_nothing_selected(self, filler, mock_page):
        """A successful click that opens a dropdown but selects nothing must still
        clear the mask so it doesn't trap later fields."""
        page = mock_page()
        input_el = AsyncMock()
        input_el.click = AsyncMock()
        filler._try_dropdown_options = AsyncMock(return_value=False)
        filler._dismiss_dropdown_mask = AsyncMock(return_value=False)

        assert await filler._try_click_dropdown(input_el, page) is False
        filler._dismiss_dropdown_mask.assert_called_once()

    async def test_no_cleanup_when_option_selected(self, filler, mock_page):
        """A clean selection closes the widget itself; no mask cleanup needed."""
        page = mock_page()
        input_el = AsyncMock()
        input_el.click = AsyncMock()
        filler._try_dropdown_options = AsyncMock(return_value=True)
        filler._dismiss_dropdown_mask = AsyncMock(return_value=False)

        assert await filler._try_click_dropdown(input_el, page) is True
        filler._dismiss_dropdown_mask.assert_not_called()


class TestFillDisabled:
    async def test_fill_noop_when_disabled(self, make_config, mock_page):
        from config_loader import FormConfig
        cfg = make_config(form_filling=FormConfig(enabled=False))
        filler = FormFiller(cfg)
        page = mock_page()
        await filler.fill(page)
        page.wait_for_timeout.assert_not_called()

    async def test_fill_noop_when_form_filling_none(self, make_config, mock_page):
        cfg = make_config(form_filling=None)
        filler = FormFiller(cfg)
        page = mock_page()
        await filler.fill(page)
        page.wait_for_timeout.assert_not_called()
