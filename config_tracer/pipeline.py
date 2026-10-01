"""The scan pipeline: crawl -> quarantine -> resolve -> probe -> report, with
the resolve/probe step repeated, a bounded number of hops, for the cross-origin
redirect targets each round of probing discloses.

Pure orchestration of the async core with no persistence, so it can be run
and tested without a database. This is what the worker executes per scan."""

import logging
from urllib.parse import urlparse

from .crawl import crawl
from .extract import _classify_url
from .models import AuthInfo, ConfigSource, ProbeResult
from .probe import (
    build_auth_map, probe_urls_with_roots, redirect_sources, synthesized_sources,
)
from .report import ScanReport, build_report
from .resolve import resolve_hosts
from .settings import ScanSettings

log = logging.getLogger(__name__)

# How many rounds of cross-origin redirect targets to resolve and probe beyond
# the config URLs themselves (hop 0). A redirect loop across origins ends on its
# own, because a URL is never placed in a frontier twice; the cap only bounds
# chains of *distinct* URLs, such as a redirect that mints a fresh nonce on every
# request. Real chains (http -> https -> SSO -> IdP) are two or three hops. A
# module constant rather than a ScanSettings field: that model is frozen and
# snapshotted onto each scan row, so a field would change the stored contract
# for a knob nobody tunes.
_MAX_REDIRECT_HOPS = 5


async def _resolve_and_probe(
    urls: list[str], settings: ScanSettings,
) -> tuple[dict[str, AuthInfo], list[dict], dict[str, list[str]], list[ConfigSource]]:
    """Resolve and probe `urls`, then the cross-origin redirect targets those
    probes disclose, and theirs, up to _MAX_REDIRECT_HOPS rounds.

    Returns (auth_map, unresolved, ip_map, probe_sources): the probe map over
    every URL of every hop, the DNS failures and successes across all hops, and
    the ConfigSources the probes disclosed: one per path whose undisclosed
    400/401/403 set off a kept host-root probe (origin `synthesized: <path>`)
    naming that root, and one per redirecting probe (origin `redirect: <url>`)
    naming what it pointed at. The caller adds those sources to the crawl's, so
    build_report places each root and target like any discovered URL — a target
    under its own service, which is dns_failed if its host did not resolve, or
    in quarantine — with provenance.

    `urls` must already be unique and clean (_classify_url is None). Every URL
    ever placed in a frontier is remembered, resolvable or not, so a later hop
    never re-resolves, re-probes or re-lists it; that is also what closes a
    redirect loop. A redirect source is kept whether or not its target is new,
    so a URL the config named that a redirect also points at still gains the
    `redirect:` provenance. Targets left over when the cap is hit are dropped,
    sources included: naming them without resolving them would put a service in
    the report with no addresses and no probes.

    build_auth_map runs once over the probes of every hop, and a path probe of
    a URL beats its root probe there. So a host root that one hop synthesized
    and another probed as a path — a config URL or a redirect target — keeps the
    path probe and carries both provenances, `synthesized:` and the other. The
    price is one redundant request in that case, since probe_urls_with_roots
    only dedups roots within one call."""
    unresolved: list[dict] = []
    ip_map: dict[str, list[str]] = {}
    path_probes: list[ProbeResult] = []
    root_probes: list[ProbeResult] = []
    found_sources: list[ConfigSource] = []

    probed: set[str] = set()
    frontier = list(urls)
    hop = 0
    while frontier:
        if hop:
            log.info("Following %d cross-origin redirect target(s) (hop %d/%d)",
                     len(frontier), hop, _MAX_REDIRECT_HOPS)
        probed.update(frontier)

        unresolved_set = {entry["host"] for entry in unresolved}
        hosts = sorted({urlparse(u).hostname for u in frontier if urlparse(u).hostname})
        new_hosts = [h for h in hosts if h not in ip_map and h not in unresolved_set]
        if new_hosts:
            log.info("Resolving %d host(s)", len(new_hosts))
            failures, resolved = await resolve_hosts(
                new_hosts, timeout=settings.dns_timeout_s,
                max_concurrent=settings.dns_concurrency,
            )
            unresolved.extend(failures)
            ip_map.update(resolved)
            unresolved_set.update(entry["host"] for entry in failures)

        paths: list[ProbeResult] = []
        roots: list[ProbeResult] = []
        probeable = [u for u in frontier if urlparse(u).hostname not in unresolved_set]
        if probeable:
            skipped = len(frontier) - len(probeable)
            log.info("Probing %d URL(s) for authentication methods%s", len(probeable),
                     f" (skipping {skipped} on unresolved hosts)" if skipped else "")
            paths, roots = await probe_urls_with_roots(
                probeable,
                timeout=settings.probe_timeout_s,
                max_concurrent=settings.probe_concurrency,
            )
            if roots:
                log.info("Probed %d host root(s) to disclose undisclosed auth", len(roots))
            path_probes.extend(paths)
            root_probes.extend(roots)

        hop_sources = redirect_sources(paths + roots)
        next_frontier = [
            t for t in dict.fromkeys(u for s in hop_sources for u in s.urls_found)
            if _classify_url(t) is None and t not in probed
        ]
        if next_frontier and hop == _MAX_REDIRECT_HOPS:
            log.warning("Redirect chain exceeded %d hop(s); %d target(s) not followed",
                        _MAX_REDIRECT_HOPS, len(next_frontier))
            dropped = set(next_frontier)
            hop_sources = [s for s in hop_sources if s.urls_found[0] not in dropped]
            next_frontier = []
        # A hop's roots were probed already, so they name no frontier. Their
        # sources go first: the path probes that set them off came before any
        # root's redirect.
        found_sources.extend(synthesized_sources(paths, roots))
        found_sources.extend(hop_sources)
        frontier = next_frontier
        hop += 1

    # resolve_hosts sorts per call; the report promises one order across hops.
    unresolved.sort(key=lambda entry: entry["host"])
    return build_auth_map(path_probes, root_probes), unresolved, ip_map, found_sources


async def run_scan(seeds: list[str], settings: ScanSettings) -> ScanReport:
    """Run one full scan over `seeds` (the target URL first, then any extras)."""
    if not seeds:
        raise ValueError("run_scan needs at least one seed URL")

    sources = await crawl(
        list(seeds),
        timeout=settings.nav_timeout_ms,
        wait_after_load=settings.wait_after_load_ms,
        interact_budget_ms=settings.interact_budget_ms,
        follow_links=settings.follow_links,
        max_pages=settings.max_pages,
    )

    all_urls = [u for src in sources for u in src.urls_found]
    unique_urls = [u for u in dict.fromkeys(all_urls) if _classify_url(u) is None]

    auth_map, unresolved, ip_map, probe_srcs = await _resolve_and_probe(
        unique_urls, settings)
    report = build_report(sources + probe_srcs, auth_map, unresolved, ip_map)
    for s in report.suspect_urls:
        log.warning("Not probing suspect URL %s (%s); found in %s",
                    s.url, s.reason, ", ".join(s.sources))
    return report
