from enum import Enum


class AuthMethod(str, Enum):
    """The combined vocabulary of both scanners. The interceptor never emits
    login_redirect or dns_failed, and the tracer never emits kerberos or
    api_key; every other value can come from either."""
    ntlm = "ntlm"
    kerberos = "kerberos"
    negotiate = "negotiate"
    oauth = "oauth"
    login_redirect = "login_redirect"
    basic = "basic"
    bearer = "bearer"
    api_key = "api_key"
    other = "other"
    unauthenticated = "unauthenticated"
    no_response = "no_response"
    dns_failed = "dns_failed"
    unknown = "unknown"


class Severity(str, Enum):
    blocker = "blocker"
    review = "review"
    cleared = "cleared"
    # Already published through the F5, by a workaround the scanners cannot
    # see. Set only from the published-origins registry, in
    # core.jobs._recompute_services, whatever the auth method says;
    # translate.severity_for never returns it. Where cleared means the F5 can
    # publish the origin and someone still has to, published means nothing
    # is left to configure.
    published = "published"


class ScanStatus(str, Enum):
    """Derived from the scan's jobs (core.jobs.scan_status)."""
    queued = "queued"
    running = "running"
    completed = "completed"
    # At least one of the scan's jobs completed and the rest failed.
    partial = "partial"
    failed = "failed"
    cancelled = "cancelled"


class Scanner(str, Enum):
    interceptor = "interceptor"
    tracer = "tracer"


class SourceKind(str, Enum):
    """Where a scanner found a service's origin (api.models.Source). The first
    five are the tracer's provenance kinds, the prefix of each string in
    urls.sources; page is the interceptor's, a urls.page_url."""
    # A config the page loaded, a JS bundle it loaded, or an element of the
    # page, that named a URL of the origin.
    network = "network"
    js = "js"
    dom = "dom"
    # A probed URL whose redirect pointed at the origin.
    redirect = "redirect"
    # The origin's root, which the tracer probed on its own initiative after
    # the URL named here answered 4xx.
    synthesized = "synthesized"
    # A page the interceptor's browser was on when it called the origin.
    page = "page"


class JobStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"
