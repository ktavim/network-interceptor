"""Reactive login handling: triggered when the crawler lands on the configured login URL."""
import json
import logging
import os
import time
from urllib.parse import urlparse

from playwright.async_api import Error as PlaywrightError, Page, TimeoutError as PlaywrightTimeoutError

from config_loader import LoginConfig

from ..origin import origin_of

logger = logging.getLogger(__name__)


def _is_login_url(url: str, cfg: LoginConfig) -> bool:
    if origin_of(url) != origin_of(cfg.login_url):
        return False
    path = urlparse(url).path.rstrip('/')
    login_path = urlparse(cfg.login_url).path.rstrip('/')
    return path == login_path or path.startswith(login_path + '/')


def is_on_login_page(page: Page, cfg: LoginConfig) -> bool:
    return _is_login_url(page.url, cfg)


def storage_state_valid(cfg: LoginConfig) -> bool:
    """Cheap local check that the stored state could plausibly hold a session.

    Rejects files that are structurally not a Playwright storage state or that
    contain no usable session material (no unexpired cookies and no localStorage
    entries). Whether the session actually still works is left to the reactive
    login flow, which recovers if a reused state lands on the login page.
    """
    path = cfg.storage_state_path
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        return False
    try:
        with open(path, 'r', encoding='utf-8') as f:
            state = json.load(f)
    except (json.JSONDecodeError, OSError):
        return False

    if not isinstance(state, dict):
        return False
    cookies = state.get('cookies')
    origins = state.get('origins')
    if not isinstance(cookies, list) or not isinstance(origins, list):
        return False

    now = time.time()
    has_live_cookie = any(
        isinstance(c, dict) and (c.get('expires', -1) == -1 or c.get('expires', -1) > now)
        for c in cookies
    )
    has_local_storage = any(
        isinstance(o, dict) and o.get('localStorage')
        for o in origins
    )
    return has_live_cookie or has_local_storage


async def perform_login(page: Page, cfg: LoginConfig, app_url: str) -> None:
    """Drive the login flow on `page`, which is already sitting on the login URL.

    Waits until the URL is back on `app_url`'s origin and off the login URL —
    an off-origin SSO/IdP hop keeps the wait pending until the redirect back —
    then re-navigates to `app_url` to verify the session is authorized (the
    document response must not be an error status) before persisting it to
    `cfg.storage_state_path`. This also normalizes where the crawl resumes:
    on `app_url` itself rather than wherever the login redirect chain landed.
    """
    logger.info("Performing login at %s", page.url)

    app_origin = origin_of(app_url)
    await _fill_and_submit(page, cfg)

    try:
        await page.wait_for_url(
            lambda url: origin_of(url) == app_origin and not _is_login_url(url, cfg),
            timeout=cfg.post_login_wait_ms + 30000,
        )
    except PlaywrightTimeoutError as e:
        raise RuntimeError(
            f"Login did not land back on {app_url} away from {cfg.login_url}"
        ) from e

    try:
        await page.wait_for_load_state("networkidle", timeout=cfg.post_login_wait_ms + 5000)
    except PlaywrightTimeoutError:
        logger.debug("networkidle wait timed out after login; continuing")

    response = await page.goto(app_url)
    if response is not None and response.status >= 400:
        raise RuntimeError(
            f"Login completed but {app_url} returned HTTP {response.status}"
        )

    await page.context.storage_state(path=cfg.storage_state_path)
    logger.info("Login successful; storage_state saved to %s", cfg.storage_state_path)


async def _dispatch_form_events(page: Page, selector: str) -> None:
    """Fire synthetic input/change/blur so framework-driven forms register the typed value.

    Best-effort: a field that doesn't handle a given event is not fatal. We swallow only
    Playwright-level failures (and log them) rather than masking arbitrary Python errors.
    """
    for event in ("input", "change", "blur"):
        try:
            await page.dispatch_event(selector, event)
        except PlaywrightError as e:
            logger.debug("dispatch_event(%r, %r) failed: %s", selector, event, e)


async def _fill_and_submit(page: Page, cfg: LoginConfig) -> None:
    await page.wait_for_selector(cfg.username_selector, timeout=10000)
    await page.fill(cfg.username_selector, cfg.username)
    await page.fill(cfg.password_selector, cfg.password)

    await _dispatch_form_events(page, cfg.username_selector)
    await _dispatch_form_events(page, cfg.password_selector)

    await page.click(cfg.submit_selector)
