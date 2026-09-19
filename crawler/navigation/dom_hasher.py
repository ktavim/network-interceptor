"""DOM fingerprinting and deduplication tracking."""
import hashlib
import logging
from typing import Set

from playwright.async_api import Page

from .selectors import INTERACTIVE_SELECTORS

logger = logging.getLogger(__name__)


class DOMHasher:
    """Generate and track DOM/overlay fingerprints to detect duplicate pages."""

    def __init__(self):
        self.visited_dom_hashes: Set[str] = set()
        self.visited_overlay_hashes: Set[str] = set()

    def is_dom_seen(self, dom_hash: str) -> bool:
        return dom_hash in self.visited_dom_hashes

    def mark_dom_seen(self, dom_hash: str):
        self.visited_dom_hashes.add(dom_hash)

    def is_overlay_seen(self, overlay_hash: str) -> bool:
        return overlay_hash in self.visited_overlay_hashes

    def mark_overlay_seen(self, overlay_hash: str):
        self.visited_overlay_hashes.add(overlay_hash)

    async def get_dom_hash(self, page: Page) -> str:
        """Generate hash of meaningful DOM structure to detect duplicate pages."""
        try:
            fingerprint = await page.evaluate("""() => {
                const SKIP = new Set(['SCRIPT','STYLE','SVG','NOSCRIPT']);
                const URL_ATTRS = new Set(['href','src','action']);
                const KEEP_ATTRS = ['href','src','action','type','name','role'];

                function normUrl(u) {
                    if (!u) return '';
                    try { return new URL(u, location.origin).pathname; }
                    catch(e) { return u; }
                }

                function walk(node) {
                    if (!node) return '';
                    let out = '';
                    for (let c = node.firstChild; c; c = c.nextSibling) {
                        if (c.nodeType === 8) continue;
                        if (c.nodeType === 3) {
                            let t = c.textContent.trim().replace(/\\s+/g, ' ');
                            if (t) out += t;
                            continue;
                        }
                        if (c.nodeType !== 1) continue;
                        let tag = c.tagName;
                        if (SKIP.has(tag)) continue;
                        if (tag === 'INPUT' && c.type === 'hidden') continue;
                        let lt = tag.toLowerCase();
                        out += '<' + lt;
                        for (let a of KEEP_ATTRS) {
                            let v = c.getAttribute(a);
                            if (v != null) {
                                if (URL_ATTRS.has(a)) v = normUrl(v);
                                out += ' ' + a + '="' + v + '"';
                            }
                        }
                        out += '>';
                        out += walk(c);
                        out += '</' + lt + '>';
                    }
                    return out;
                }

                return walk(document.body);
            }""")
            if not fingerprint:
                return ""
            return hashlib.md5(fingerprint.encode()).hexdigest()
        except Exception:
            return ""

    async def get_overlay_hash(self, container) -> str:
        """Fingerprint an overlay by its interactive elements' tags and text."""
        interactive = await container.query_selector_all(INTERACTIVE_SELECTORS)
        parts = []
        for el in interactive:
            try:
                tag = await el.evaluate('el => el.tagName.toLowerCase()')
                text = (await el.text_content() or '').strip().lower()
                parts.append(f"{tag}:{text}")
            except Exception:
                continue
        parts.sort()
        fingerprint = '|'.join(parts)
        return hashlib.md5(fingerprint.encode()).hexdigest()
