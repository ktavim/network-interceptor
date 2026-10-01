"""URL extraction from parsed JSON / raw text, plus JS-object sanitization."""

import json
import logging
import re
import string
from urllib.parse import urlparse

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------

URL_RE = re.compile(r'https?://[^\s"\'<>}\]\)]+')


def _clean_url(url: str) -> str:
    return url.rstrip(".,;:)\\")


_VALID_HOSTNAME_CHARS = set(string.ascii_letters + string.digits + ".-")


def _classify_url(url: str) -> str | None:
    """Return a 'suspect' reason if the URL should be quarantined, else None."""
    if "${" in url or "`" in url:
        return "template"
    host = urlparse(url).hostname
    if not host:
        return "bad_host"
    if not all(c in _VALID_HOSTNAME_CHARS for c in host):
        return "bad_host"
    return None


def _partition_urls(urls: list[str]) -> tuple[list[str], list[tuple[str, str]]]:
    """Split URLs into (clean, [(suspect_url, reason), ...])."""
    clean: list[str] = []
    suspect: list[tuple[str, str]] = []
    for u in urls:
        reason = _classify_url(u)
        if reason is None:
            clean.append(u)
        else:
            suspect.append((u, reason))
    return clean, suspect


def extract_urls(obj, seen: set[str] | None = None) -> list[str]:
    """Recursively extract http/https URLs from a parsed JSON structure."""
    if seen is None:
        seen = set()
    urls: list[str] = []

    if isinstance(obj, str):
        for m in URL_RE.findall(obj):
            clean = _clean_url(m)
            if clean not in seen:
                seen.add(clean)
                urls.append(clean)
    elif isinstance(obj, dict):
        for v in obj.values():
            urls.extend(extract_urls(v, seen))
    elif isinstance(obj, list):
        for item in obj:
            urls.extend(extract_urls(item, seen))
    return urls


def extract_urls_from_text(text: str) -> list[str]:
    """Regex fallback: pull URLs directly from raw text."""
    seen: set[str] = set()
    urls: list[str] = []
    for m in URL_RE.findall(text):
        clean = _clean_url(m)
        if clean not in seen:
            seen.add(clean)
            urls.append(clean)
    return urls


def strip_js_block_comments(text: str) -> str:
    """Drop `/* */` block comments from JavaScript source, leaving string-literal
    contents untouched.

    Used before regex URL extraction on JS bodies so URLs that live only in
    license banners don't surface as service dependencies. A URL that also
    appears in real code is still captured, because extraction dedupes; only
    comment-only URLs disappear.

    Block comments *only*, on purpose. This is a small lexical scanner, not a JS
    parser, and its cardinal duty is never to drop a real URL. Block comments are
    the one comment form that can be stripped with that guarantee: in code
    position `/*` unambiguously opens a comment (a regex can't begin with `*`,
    and it's never division), and `*/` unambiguously closes it — so scanning one
    can't desync the string tracking, and a real URL inside a string is never at
    risk. `//` line comments are deliberately NOT stripped: telling a `//`
    comment apart from the `//` inside a regex literal like `/https?:\\/\\//`
    needs full regex/division disambiguation, which is unreliable on minified
    bundles and — when wrong — corrupts string tracking and swallows real URLs.
    License banners, the noise this targets, are block
    comments regardless; the residual `// ...` URL is rare in built assets and
    left in as harmless noise, the safe direction.

    String literals ('...', "...", `...`) are tracked (with escapes) so the `/*`
    or `//` inside a real `"https://host"` is never mistaken for a comment.
    """
    out: list[str] = []
    i, n = 0, len(text)
    quote: str | None = None       # active string delimiter, else None

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if quote is not None:                      # inside a string literal
            out.append(c)
            if c == "\\" and i + 1 < n:            # keep the escaped char verbatim
                out.append(nxt)
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
        elif c == "/" and nxt == "*":              # block comment -> drop to */
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
        elif c in "'\"`":                          # string literal opens
            quote = c
            out.append(c)
            i += 1
        else:                                      # ordinary code character
            out.append(c)
            i += 1

    return "".join(out)


# ---------------------------------------------------------------------------
# JSON sanitization (JS object -> JSON best-effort)
# ---------------------------------------------------------------------------

def sanitize_js_object(text: str) -> str:
    text = re.sub(r"//.*?$", "", text, flags=re.MULTILINE)   # line comments
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)   # block comments
    text = re.sub(r"'", '"', text)                            # single -> double quotes
    text = re.sub(r",\s*([}\]])", r"\1", text)               # trailing commas
    return text


def try_parse_json(text: str) -> tuple[object | None, str | None]:
    """Try to parse text as JSON, with JS-object sanitization fallback."""
    try:
        return json.loads(text), None
    except (json.JSONDecodeError, ValueError):
        pass
    try:
        return json.loads(sanitize_js_object(text)), None
    except (json.JSONDecodeError, ValueError) as e:
        return None, str(e)


def urls_from_payload(text: str, origin: str) -> list[str]:
    """URLs in a payload expected to be JSON: extracted from its parsed
    structure, or regex-scraped when it won't parse. A failed parse is logged
    against `origin` even when the scrape finds nothing, since URLs the
    structure held but the regex misses are lost either way."""
    parsed, err = try_parse_json(text)
    if err is None:
        return extract_urls(parsed)
    log.warning("Could not parse %s as JSON; regex-scraping it instead: %s", origin, err)
    return extract_urls_from_text(text)
