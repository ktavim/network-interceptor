"""Report assembly: collapse per-URL probe evidence into per-service verdicts.

`build_report` is the pure, I/O-free join of the three passes a scan runs —
extraction (ConfigSources), DNS resolution, and HTTP probing — into one
ScanReport that the persistence layer stores and the API reads back.
"""

from dataclasses import dataclass, field

from .extract import _partition_urls
from .models import AuthInfo, AuthMethod, ConfigSource, HttpMethod, Origin, _VERDICT_PRECEDENCE


def _collapse_host_verdict(verdicts: set[AuthMethod]) -> AuthMethod | None:
    """Pick the single headline AuthMethod for a host from the distinct verdicts
    seen across its probed URLs, by _VERDICT_PRECEDENCE. Returns None when there
    are no verdicts, i.e. nothing was probed; a service whose every probe hit a
    transport error collapses to NO_RESPONSE. A service on a host that failed
    DNS takes no part: build_report sets its DNS_FAILED directly."""
    for method in _VERDICT_PRECEDENCE:
        if method in verdicts:
            return method
    return None


@dataclass
class UrlEvidence:
    """Everything known about one URL: its own probe result and its provenance.

    Probe fields are None when the URL was never probed, with one exception: a
    URL on a host that failed DNS has `detected_method` DNS_FAILED and the
    lookup's `error`, since that lookup is the one thing learned about it.
    `sources` is every origin the URL was learned from, in discovery order, and
    a scan names at least one for every URL: a config (`network:`, `js:`,
    `dom:`), a probed URL whose redirect pointed here (`redirect: <url>`), or,
    for a host root probed on our own initiative, each path whose undisclosed
    400/401/403 prompted that probe (`synthesized: <path>`). A root with only
    `synthesized:` sources is one nothing named."""
    url: str
    http_method: HttpMethod | None = None
    status_code: int | None = None
    www_authenticate: str | None = None
    location: str | None = None
    detected_method: AuthMethod | None = None
    error: str | None = None
    sources: list[str] = field(default_factory=list)


@dataclass
class ServiceReport:
    """One origin — a (scheme, host, port) triple — and the verdict collapsed
    from its URLs. An origin whose host failed DNS is a service too, so every
    dependency the app named is listed: no `ips`, nothing probed, and the
    verdict DNS_FAILED, on it and on each of its URLs."""
    origin: Origin
    ips: list[str]
    # None only when nothing was probed: a scan never produces that, and the
    # database refuses to store it.
    auth_verdict: AuthMethod | None
    urls_probed: int
    urls: list[UrlEvidence]  # sorted by url

    @property
    def url_map(self) -> dict[str, UrlEvidence]:
        return {u.url: u for u in self.urls}

    @property
    def verdict_url(self) -> str | None:
        """A sample of the URLs that produced `auth_verdict`, for showing a
        verdict's provenance: of the URLs whose own `detected_method` is the
        verdict, the first in code-point order, so a rescan that finds the same
        URLs picks the same one. It is one of possibly several. None exactly
        when `auth_verdict` is."""
        if self.auth_verdict is None:
            return None
        return min((u.url for u in self.urls if u.detected_method is self.auth_verdict),
                   default=None)


@dataclass
class SuspectUrl:
    """A URL quarantined before probing as malformed or templated. The pipeline
    logs it; it is not stored."""
    url: str
    reason: str
    sources: list[str]


@dataclass
class ScanReport:
    services: list[ServiceReport]   # sorted by Origin.sort_key: host, port, scheme
    suspect_urls: list[SuspectUrl]  # sorted by url

    @property
    def service_map(self) -> dict[str, ServiceReport]:
        """Services by Origin.key (`scheme://host[:port]`, default port elided)."""
        return {s.origin.key: s for s in self.services}


def _url_evidence(url: str,
                  info: AuthInfo | None,
                  sources: list[str] | None = None) -> UrlEvidence:
    p = info.probe_result if info is not None else None
    return UrlEvidence(
        url=url,
        http_method=p.http_method if p is not None else None,
        status_code=p.status_code if p is not None else None,
        www_authenticate=p.www_authenticate if p is not None else None,
        location=p.location if p is not None else None,
        detected_method=p.detected_method if p is not None else None,
        error=p.error if p is not None else None,
        sources=list(sources or []),
    )


def build_report(
    sources: list[ConfigSource],
    auth_map: dict[str, AuthInfo] | None = None,
    unresolved: list[dict] | None = None,
    ip_map: dict[str, list[str]] | None = None,
) -> ScanReport:
    """Join extraction, DNS, and probe results into a ScanReport.

    `unresolved` is the failure list from resolve_hosts ([{host, error}]) and
    `ip_map` its success map. Services are keyed by Origin, and every clean URL
    is placed under exactly one. A service on a failed host is reported, not
    dropped — see ServiceReport. A failed host that no clean URL names has no
    origin to report under and is left out; a scan never produces one, since
    the pipeline only resolves the hosts of the URLs it was handed.
    """
    auth_map = auth_map or {}
    unresolved = unresolved or []
    ip_map = ip_map or {}

    all_clean: set[str] = set()
    url_sources: dict[str, list[str]] = {}
    suspect_index: dict[str, dict] = {}
    for src in sources:
        clean, suspect = _partition_urls(src.urls_found)
        all_clean.update(clean)
        for url in clean:
            origins = url_sources.setdefault(url, [])
            if src.origin not in origins:
                origins.append(src.origin)
        for url, reason in suspect:
            entry = suspect_index.setdefault(url, {"reason": reason, "sources": []})
            if src.origin not in entry["sources"]:
                entry["sources"].append(src.origin)

    services: set[Origin] = set()
    service_urls: dict[Origin, list[str]] = {}
    for u in sorted(all_clean):
        origin = Origin.from_url(u)
        if origin is not None:
            services.add(origin)
            service_urls.setdefault(origin, []).append(u)

    dns_errors = {e["host"]: e["error"] for e in unresolved}

    service_auth: dict[Origin, dict[str, AuthInfo]] = {}
    for url, info in auth_map.items():
        origin = Origin.from_url(url)
        if origin is None:
            continue
        service_auth.setdefault(origin, {})[url] = info

    service_reports: list[ServiceReport] = []
    for origin in sorted(services, key=lambda o: o.sort_key):
        dns_error = dns_errors.get(origin.host)
        if dns_error is not None:
            # A name that doesn't resolve from the scanner's vantage point is a
            # finding on an internal estate, and the path and provenance are
            # what make it one, so each URL is kept with the lookup's error.
            service_reports.append(ServiceReport(
                origin=origin,
                ips=[],
                auth_verdict=AuthMethod.DNS_FAILED,
                urls_probed=0,
                urls=[UrlEvidence(url=url, detected_method=AuthMethod.DNS_FAILED,
                                  error=dns_error, sources=list(url_sources[url]))
                      for url in service_urls[origin]],
            ))
            continue
        infos = service_auth.get(origin, {})
        probes = [(url, i.probe_result) for url, i in infos.items()]
        service_reports.append(ServiceReport(
            origin=origin,
            ips=list(ip_map.get(origin.host, [])),
            auth_verdict=_collapse_host_verdict({p.detected_method for _, p in probes if p}),
            urls_probed=len(probes),
            urls=[_url_evidence(url, infos.get(url), url_sources.get(url))
                  for url in sorted(set(service_urls.get(origin, [])) | set(infos))],
        ))

    suspect_urls = [
        SuspectUrl(url=url, reason=entry["reason"], sources=list(entry["sources"]))
        for url, entry in sorted(suspect_index.items())
    ]

    return ScanReport(
        services=service_reports,
        suspect_urls=suspect_urls,
    )
