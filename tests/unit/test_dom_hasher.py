"""Tests for crawler.navigation.dom_hasher.DOMHasher."""
import pytest
from unittest.mock import AsyncMock, MagicMock

from crawler.navigation.dom_hasher import DOMHasher


@pytest.fixture
def hasher():
    return DOMHasher()


class TestHashSets:
    def test_initial_empty(self, hasher):
        assert hasher.visited_dom_hashes == set()
        assert hasher.visited_overlay_hashes == set()

    def test_mark_and_check_dom(self, hasher):
        assert hasher.is_dom_seen("abc") is False
        hasher.mark_dom_seen("abc")
        assert hasher.is_dom_seen("abc") is True

    def test_mark_and_check_overlay(self, hasher):
        assert hasher.is_overlay_seen("ov") is False
        hasher.mark_overlay_seen("ov")
        assert hasher.is_overlay_seen("ov") is True

    def test_dom_and_overlay_sets_independent(self, hasher):
        hasher.mark_dom_seen("x")
        assert hasher.is_overlay_seen("x") is False


class TestGetDomHash:
    async def test_returns_md5_of_fingerprint(self, hasher):
        page = MagicMock()
        page.evaluate = AsyncMock(return_value="<body><h1>hi</h1></body>")
        h = await hasher.get_dom_hash(page)
        assert len(h) == 32  # md5 hex

    async def test_stable_for_same_fingerprint(self, hasher):
        page = MagicMock()
        page.evaluate = AsyncMock(return_value="<div>a</div>")
        h1 = await hasher.get_dom_hash(page)
        h2 = await hasher.get_dom_hash(page)
        assert h1 == h2

    async def test_changes_with_different_fingerprint(self, hasher):
        page = MagicMock()
        page.evaluate = AsyncMock(side_effect=["<a></a>", "<b></b>"])
        h1 = await hasher.get_dom_hash(page)
        h2 = await hasher.get_dom_hash(page)
        assert h1 != h2

    async def test_empty_fingerprint_returns_empty(self, hasher):
        page = MagicMock()
        page.evaluate = AsyncMock(return_value="")
        assert await hasher.get_dom_hash(page) == ""

    async def test_exception_returns_empty(self, hasher):
        page = MagicMock()
        page.evaluate = AsyncMock(side_effect=Exception("page closed"))
        assert await hasher.get_dom_hash(page) == ""


class TestGetOverlayHash:
    async def test_hashes_interactive_children(self, hasher):
        container = MagicMock()

        el1 = AsyncMock()
        el1.evaluate = AsyncMock(return_value="button")
        el1.text_content = AsyncMock(return_value="OK")

        el2 = AsyncMock()
        el2.evaluate = AsyncMock(return_value="a")
        el2.text_content = AsyncMock(return_value="Link")

        container.query_selector_all = AsyncMock(return_value=[el1, el2])

        h = await hasher.get_overlay_hash(container)
        assert len(h) == 32

    async def test_order_independent(self, hasher):
        def make_container(pairs):
            c = MagicMock()
            els = []
            for tag, text in pairs:
                e = AsyncMock()
                e.evaluate = AsyncMock(return_value=tag)
                e.text_content = AsyncMock(return_value=text)
                els.append(e)
            c.query_selector_all = AsyncMock(return_value=els)
            return c

        h1 = await hasher.get_overlay_hash(make_container([("button", "OK"), ("a", "go")]))
        h2 = await hasher.get_overlay_hash(make_container([("a", "go"), ("button", "OK")]))
        assert h1 == h2

    async def test_differs_when_content_differs(self, hasher):
        def make_container(text):
            c = MagicMock()
            e = AsyncMock()
            e.evaluate = AsyncMock(return_value="button")
            e.text_content = AsyncMock(return_value=text)
            c.query_selector_all = AsyncMock(return_value=[e])
            return c

        h1 = await hasher.get_overlay_hash(make_container("OK"))
        h2 = await hasher.get_overlay_hash(make_container("Cancel"))
        assert h1 != h2

    async def test_empty_container(self, hasher):
        container = MagicMock()
        container.query_selector_all = AsyncMock(return_value=[])
        h = await hasher.get_overlay_hash(container)
        assert len(h) == 32
