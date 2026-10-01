"""Well-known build-manifest probing and chunk fetching."""

import logging
import re
from urllib.parse import urljoin

from .capture import MAX_PAYLOAD_BYTES
from .extract import try_parse_json

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Asset manifest probing
# ---------------------------------------------------------------------------

# Well-known manifest paths that bundlers expose
MANIFEST_PATHS = (
    "/asset-manifest.json",          # Create React App
    "/manifest.json",                # generic
    "/.vite/manifest.json",          # Vite (production manifest)
    "/build/manifest.json",          # Remix / some Vite setups
    "/static/manifest.json",         # generic /static prefix
)

# Match webpack/Vite-style chunk references inside manifest JSON / _buildManifest.js
_CHUNK_LIKE_RE = re.compile(r'["\']([^"\']*\.(?:m?js|cjs))["\']')


def _extract_chunk_paths_from_manifest(text: str) -> list[str]:
    """Pull plausible chunk paths out of a manifest body (JSON or JS)."""
    paths: list[str] = []
    seen: set[str] = set()

    parsed, _ = try_parse_json(text)
    if parsed is not None:
        def walk(node):
            if isinstance(node, str):
                if node.endswith((".js", ".mjs", ".cjs")) and node not in seen:
                    seen.add(node)
                    paths.append(node)
            elif isinstance(node, dict):
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)
        walk(parsed)

    # Always also regex-scan: handles _buildManifest.js (not JSON) and JSON
    # values where chunk paths are embedded in templated strings.
    for m in _CHUNK_LIKE_RE.findall(text):
        if m and m not in seen:
            seen.add(m)
            paths.append(m)

    return paths


async def _probe_manifests(
    context,
    base_url: str,
    captured_js: list[tuple[str, str]],
    captured_json: list[tuple[str, str]],
    seen_urls: set[str],
) -> int:
    """Try well-known manifest paths; fetch any referenced chunks as text.
    Returns number of chunks captured."""
    chunks_added = 0

    for manifest_rel in MANIFEST_PATHS:
        manifest_url = urljoin(base_url, manifest_rel)
        if manifest_url in seen_urls:
            continue
        try:
            resp = await context.request.get(manifest_url, timeout=5000)
            if resp.status < 200 or resp.status >= 300:
                continue
            body = await resp.text()
        except Exception:
            continue
        if not body or len(body) > MAX_PAYLOAD_BYTES:
            continue

        # SPAs typically serve their index.html with 200 for any unknown
        # path. Only treat the response as a manifest if it's actually JSON
        # by content-type or by parseability.
        ct = resp.headers.get("content-type", "").lower()
        parsed_manifest, _ = try_parse_json(body)
        if "json" not in ct and parsed_manifest is None:
            continue

        # The manifest itself often contains URLs worth harvesting
        captured_json.append((manifest_url, body))
        seen_urls.add(manifest_url)
        log.info("Manifest found: %s", manifest_url)

        chunk_paths = _extract_chunk_paths_from_manifest(body)
        for chunk_path in chunk_paths:
            chunk_abs = urljoin(manifest_url, chunk_path)
            if chunk_abs in seen_urls:
                continue
            try:
                cresp = await context.request.get(chunk_abs, timeout=5000)
                if cresp.status < 200 or cresp.status >= 300:
                    continue
                cbody = await cresp.text()
                if not cbody or len(cbody) > MAX_PAYLOAD_BYTES:
                    continue
                captured_js.append((chunk_abs, cbody))
                seen_urls.add(chunk_abs)
                chunks_added += 1
            except Exception:
                continue

    return chunks_added
